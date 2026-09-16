rule TTP_XOR_WriteProcessMemory_3ce9 {
  strings:
    $key_3ce9 = { 6b 9b [2] 59 b9 [2] 5f 8c [2] 71 8c [2] 4e 90 }

  condition:
    any of them
}