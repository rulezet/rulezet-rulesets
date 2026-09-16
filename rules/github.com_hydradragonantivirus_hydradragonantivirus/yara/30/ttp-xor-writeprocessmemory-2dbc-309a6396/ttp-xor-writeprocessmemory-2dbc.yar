rule TTP_XOR_WriteProcessMemory_2dbc {
  strings:
    $key_2dbc = { 7a ce [2] 48 ec [2] 4e d9 [2] 60 d9 [2] 5f c5 }

  condition:
    any of them
}