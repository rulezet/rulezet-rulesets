rule TTP_XOR_WriteProcessMemory_689e {
  strings:
    $key_689e = { 3f ec [2] 0d ce [2] 0b fb [2] 25 fb [2] 1a e7 }

  condition:
    any of them
}