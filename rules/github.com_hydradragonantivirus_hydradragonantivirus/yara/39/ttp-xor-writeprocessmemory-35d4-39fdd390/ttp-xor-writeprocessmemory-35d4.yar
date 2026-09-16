rule TTP_XOR_WriteProcessMemory_35d4 {
  strings:
    $key_35d4 = { 62 a6 [2] 50 84 [2] 56 b1 [2] 78 b1 [2] 47 ad }

  condition:
    any of them
}