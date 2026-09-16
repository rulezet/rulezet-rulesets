rule TTP_XOR_WriteProcessMemory_50c1 {
  strings:
    $key_50c1 = { 07 b3 [2] 35 91 [2] 33 a4 [2] 1d a4 [2] 22 b8 }

  condition:
    any of them
}