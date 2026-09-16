rule TTP_XOR_WriteProcessMemory_50c4 {
  strings:
    $key_50c4 = { 07 b6 [2] 35 94 [2] 33 a1 [2] 1d a1 [2] 22 bd }

  condition:
    any of them
}