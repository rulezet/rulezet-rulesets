rule TTP_XOR_WriteProcessMemory_edbc {
  strings:
    $key_edbc = { ba ce [2] 88 ec [2] 8e d9 [2] a0 d9 [2] 9f c5 }

  condition:
    any of them
}