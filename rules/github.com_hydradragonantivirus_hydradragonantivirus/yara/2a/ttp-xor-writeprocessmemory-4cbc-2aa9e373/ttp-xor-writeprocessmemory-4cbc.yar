rule TTP_XOR_WriteProcessMemory_4cbc {
  strings:
    $key_4cbc = { 1b ce [2] 29 ec [2] 2f d9 [2] 01 d9 [2] 3e c5 }

  condition:
    any of them
}