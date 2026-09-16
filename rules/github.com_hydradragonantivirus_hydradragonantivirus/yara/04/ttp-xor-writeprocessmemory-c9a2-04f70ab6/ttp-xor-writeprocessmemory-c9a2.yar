rule TTP_XOR_WriteProcessMemory_c9a2 {
  strings:
    $key_c9a2 = { 9e d0 [2] ac f2 [2] aa c7 [2] 84 c7 [2] bb db }

  condition:
    any of them
}