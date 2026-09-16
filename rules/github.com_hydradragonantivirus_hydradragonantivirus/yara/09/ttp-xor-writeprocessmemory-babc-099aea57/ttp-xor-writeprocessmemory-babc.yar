rule TTP_XOR_WriteProcessMemory_babc {
  strings:
    $key_babc = { ed ce [2] df ec [2] d9 d9 [2] f7 d9 [2] c8 c5 }

  condition:
    any of them
}