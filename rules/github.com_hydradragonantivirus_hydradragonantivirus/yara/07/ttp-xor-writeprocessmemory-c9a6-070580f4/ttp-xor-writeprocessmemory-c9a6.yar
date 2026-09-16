rule TTP_XOR_WriteProcessMemory_c9a6 {
  strings:
    $key_c9a6 = { 9e d4 [2] ac f6 [2] aa c3 [2] 84 c3 [2] bb df }

  condition:
    any of them
}