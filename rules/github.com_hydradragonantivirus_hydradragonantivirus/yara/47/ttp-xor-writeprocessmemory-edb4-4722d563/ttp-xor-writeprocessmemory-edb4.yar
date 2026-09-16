rule TTP_XOR_WriteProcessMemory_edb4 {
  strings:
    $key_edb4 = { ba c6 [2] 88 e4 [2] 8e d1 [2] a0 d1 [2] 9f cd }

  condition:
    any of them
}