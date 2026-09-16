rule TTP_XOR_WriteProcessMemory_bbbc {
  strings:
    $key_bbbc = { ec ce [2] de ec [2] d8 d9 [2] f6 d9 [2] c9 c5 }

  condition:
    any of them
}