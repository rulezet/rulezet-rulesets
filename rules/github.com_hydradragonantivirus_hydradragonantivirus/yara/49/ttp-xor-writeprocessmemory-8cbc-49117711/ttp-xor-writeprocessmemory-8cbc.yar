rule TTP_XOR_WriteProcessMemory_8cbc {
  strings:
    $key_8cbc = { db ce [2] e9 ec [2] ef d9 [2] c1 d9 [2] fe c5 }

  condition:
    any of them
}