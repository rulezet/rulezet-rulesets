rule TTP_XOR_WriteProcessMemory_afbc {
  strings:
    $key_afbc = { f8 ce [2] ca ec [2] cc d9 [2] e2 d9 [2] dd c5 }

  condition:
    any of them
}