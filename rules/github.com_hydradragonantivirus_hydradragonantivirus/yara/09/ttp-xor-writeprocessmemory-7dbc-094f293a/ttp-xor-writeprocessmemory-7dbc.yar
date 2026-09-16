rule TTP_XOR_WriteProcessMemory_7dbc {
  strings:
    $key_7dbc = { 2a ce [2] 18 ec [2] 1e d9 [2] 30 d9 [2] 0f c5 }

  condition:
    any of them
}