rule TTP_XOR_WriteProcessMemory_65d0 {
  strings:
    $key_65d0 = { 32 a2 [2] 00 80 [2] 06 b5 [2] 28 b5 [2] 17 a9 }

  condition:
    any of them
}