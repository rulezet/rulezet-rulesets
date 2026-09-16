rule TTP_XOR_WriteProcessMemory_9dbc {
  strings:
    $key_9dbc = { ca ce [2] f8 ec [2] fe d9 [2] d0 d9 [2] ef c5 }

  condition:
    any of them
}