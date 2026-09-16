rule TTP_XOR_WriteProcessMemory_5cbc {
  strings:
    $key_5cbc = { 0b ce [2] 39 ec [2] 3f d9 [2] 11 d9 [2] 2e c5 }

  condition:
    any of them
}