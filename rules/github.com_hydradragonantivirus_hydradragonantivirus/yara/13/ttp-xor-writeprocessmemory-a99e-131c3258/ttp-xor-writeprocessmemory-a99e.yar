rule TTP_XOR_WriteProcessMemory_a99e {
  strings:
    $key_a99e = { fe ec [2] cc ce [2] ca fb [2] e4 fb [2] db e7 }

  condition:
    any of them
}