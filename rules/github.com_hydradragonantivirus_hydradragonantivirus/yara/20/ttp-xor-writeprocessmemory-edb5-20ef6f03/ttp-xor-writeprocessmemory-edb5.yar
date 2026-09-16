rule TTP_XOR_WriteProcessMemory_edb5 {
  strings:
    $key_edb5 = { ba c7 [2] 88 e5 [2] 8e d0 [2] a0 d0 [2] 9f cc }

  condition:
    any of them
}