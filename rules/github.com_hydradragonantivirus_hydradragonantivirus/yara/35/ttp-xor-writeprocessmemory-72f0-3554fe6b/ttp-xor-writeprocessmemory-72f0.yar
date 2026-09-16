rule TTP_XOR_WriteProcessMemory_72f0 {
  strings:
    $key_72f0 = { 25 82 [2] 17 a0 [2] 11 95 [2] 3f 95 [2] 00 89 }

  condition:
    any of them
}