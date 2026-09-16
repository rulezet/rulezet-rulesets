rule TTP_XOR_WriteProcessMemory_edb1 {
  strings:
    $key_edb1 = { ba c3 [2] 88 e1 [2] 8e d4 [2] a0 d4 [2] 9f c8 }

  condition:
    any of them
}