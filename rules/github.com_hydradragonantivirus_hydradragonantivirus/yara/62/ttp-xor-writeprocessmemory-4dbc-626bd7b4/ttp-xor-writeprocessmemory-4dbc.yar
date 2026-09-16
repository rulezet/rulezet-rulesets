rule TTP_XOR_WriteProcessMemory_4dbc {
  strings:
    $key_4dbc = { 1a ce [2] 28 ec [2] 2e d9 [2] 00 d9 [2] 3f c5 }

  condition:
    any of them
}