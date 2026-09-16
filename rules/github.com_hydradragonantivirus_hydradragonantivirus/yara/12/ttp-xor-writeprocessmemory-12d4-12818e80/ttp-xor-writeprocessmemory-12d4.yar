rule TTP_XOR_WriteProcessMemory_12d4 {
  strings:
    $key_12d4 = { 45 a6 [2] 77 84 [2] 71 b1 [2] 5f b1 [2] 60 ad }

  condition:
    any of them
}