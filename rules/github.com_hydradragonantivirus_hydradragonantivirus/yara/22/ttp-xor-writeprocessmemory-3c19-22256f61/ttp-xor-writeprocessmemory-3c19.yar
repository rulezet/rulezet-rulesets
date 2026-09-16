rule TTP_XOR_WriteProcessMemory_3c19 {
  strings:
    $key_3c19 = { 6b 6b [2] 59 49 [2] 5f 7c [2] 71 7c [2] 4e 60 }

  condition:
    any of them
}