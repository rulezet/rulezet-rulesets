rule TTP_XOR_WriteProcessMemory_3c59 {
  strings:
    $key_3c59 = { 6b 2b [2] 59 09 [2] 5f 3c [2] 71 3c [2] 4e 20 }

  condition:
    any of them
}