rule TTP_XOR_WriteProcessMemory_20d4 {
  strings:
    $key_20d4 = { 77 a6 [2] 45 84 [2] 43 b1 [2] 6d b1 [2] 52 ad }

  condition:
    any of them
}