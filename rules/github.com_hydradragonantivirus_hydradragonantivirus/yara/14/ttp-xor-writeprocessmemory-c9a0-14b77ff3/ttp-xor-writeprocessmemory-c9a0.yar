rule TTP_XOR_WriteProcessMemory_c9a0 {
  strings:
    $key_c9a0 = { 9e d2 [2] ac f0 [2] aa c5 [2] 84 c5 [2] bb d9 }

  condition:
    any of them
}