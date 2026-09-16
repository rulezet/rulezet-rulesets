rule TTP_XOR_WriteProcessMemory_63d4 {
  strings:
    $key_63d4 = { 34 a6 [2] 06 84 [2] 00 b1 [2] 2e b1 [2] 11 ad }

  condition:
    any of them
}