rule TTP_XOR_WriteProcessMemory_6dbc {
  strings:
    $key_6dbc = { 3a ce [2] 08 ec [2] 0e d9 [2] 20 d9 [2] 1f c5 }

  condition:
    any of them
}