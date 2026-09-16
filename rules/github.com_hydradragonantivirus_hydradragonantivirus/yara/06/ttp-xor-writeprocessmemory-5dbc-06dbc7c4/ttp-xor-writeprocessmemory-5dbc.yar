rule TTP_XOR_WriteProcessMemory_5dbc {
  strings:
    $key_5dbc = { 0a ce [2] 38 ec [2] 3e d9 [2] 10 d9 [2] 2f c5 }

  condition:
    any of them
}