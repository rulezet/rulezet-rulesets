rule TTP_XOR_WriteProcessMemory_2fbc {
  strings:
    $key_2fbc = { 78 ce [2] 4a ec [2] 4c d9 [2] 62 d9 [2] 5d c5 }

  condition:
    any of them
}