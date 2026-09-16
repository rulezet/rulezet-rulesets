rule TTP_XOR_WriteProcessMemory_c342 {
  strings:
    $key_c342 = { 94 30 [2] a6 12 [2] a0 27 [2] 8e 27 [2] b1 3b }

  condition:
    any of them
}