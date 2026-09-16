rule TTP_XOR_WriteProcessMemory_65f0 {
  strings:
    $key_65f0 = { 32 82 [2] 00 a0 [2] 06 95 [2] 28 95 [2] 17 89 }

  condition:
    any of them
}