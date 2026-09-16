rule TTP_XOR_WriteProcessMemory_78a0 {
  strings:
    $key_78a0 = { 2f d2 [2] 1d f0 [2] 1b c5 [2] 35 c5 [2] 0a d9 }

  condition:
    any of them
}