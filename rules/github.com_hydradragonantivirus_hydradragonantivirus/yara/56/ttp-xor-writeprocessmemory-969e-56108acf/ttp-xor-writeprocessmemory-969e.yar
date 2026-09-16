rule TTP_XOR_WriteProcessMemory_969e {
  strings:
    $key_969e = { c1 ec [2] f3 ce [2] f5 fb [2] db fb [2] e4 e7 }

  condition:
    any of them
}