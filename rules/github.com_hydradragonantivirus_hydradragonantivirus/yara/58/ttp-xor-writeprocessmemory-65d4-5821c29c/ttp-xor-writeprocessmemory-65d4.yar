rule TTP_XOR_WriteProcessMemory_65d4 {
  strings:
    $key_65d4 = { 32 a6 [2] 00 84 [2] 06 b1 [2] 28 b1 [2] 17 ad }

  condition:
    any of them
}