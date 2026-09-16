rule TTP_XOR_WriteProcessMemory_50c3 {
  strings:
    $key_50c3 = { 07 b1 [2] 35 93 [2] 33 a6 [2] 1d a6 [2] 22 ba }

  condition:
    any of them
}