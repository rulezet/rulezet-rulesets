rule TTP_XOR_WriteProcessMemory_1cbc {
  strings:
    $key_1cbc = { 4b ce [2] 79 ec [2] 7f d9 [2] 51 d9 [2] 6e c5 }

  condition:
    any of them
}