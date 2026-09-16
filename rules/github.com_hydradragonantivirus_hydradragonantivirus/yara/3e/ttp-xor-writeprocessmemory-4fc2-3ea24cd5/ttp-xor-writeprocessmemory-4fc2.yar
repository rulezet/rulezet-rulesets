rule TTP_XOR_WriteProcessMemory_4fc2 {
  strings:
    $key_4fc2 = { 18 b0 [2] 2a 92 [2] 2c a7 [2] 02 a7 [2] 3d bb }

  condition:
    any of them
}