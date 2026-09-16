rule TTP_XOR_WriteProcessMemory_c9f0 {
  strings:
    $key_c9f0 = { 9e 82 [2] ac a0 [2] aa 95 [2] 84 95 [2] bb 89 }

  condition:
    any of them
}