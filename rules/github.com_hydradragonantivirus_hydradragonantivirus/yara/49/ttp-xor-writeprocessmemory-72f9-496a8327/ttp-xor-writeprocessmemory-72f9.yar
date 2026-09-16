rule TTP_XOR_WriteProcessMemory_72f9 {
  strings:
    $key_72f9 = { 25 8b [2] 17 a9 [2] 11 9c [2] 3f 9c [2] 00 80 }

  condition:
    any of them
}