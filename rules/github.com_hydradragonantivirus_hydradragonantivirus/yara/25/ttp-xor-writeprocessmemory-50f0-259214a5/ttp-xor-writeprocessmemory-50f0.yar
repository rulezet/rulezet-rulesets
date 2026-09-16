rule TTP_XOR_WriteProcessMemory_50f0 {
  strings:
    $key_50f0 = { 07 82 [2] 35 a0 [2] 33 95 [2] 1d 95 [2] 22 89 }

  condition:
    any of them
}