rule TTP_XOR_WriteProcessMemory_1dbc {
  strings:
    $key_1dbc = { 4a ce [2] 78 ec [2] 7e d9 [2] 50 d9 [2] 6f c5 }

  condition:
    any of them
}