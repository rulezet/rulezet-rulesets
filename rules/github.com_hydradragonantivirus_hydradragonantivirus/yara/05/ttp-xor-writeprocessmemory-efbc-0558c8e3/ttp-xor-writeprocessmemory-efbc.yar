rule TTP_XOR_WriteProcessMemory_efbc {
  strings:
    $key_efbc = { b8 ce [2] 8a ec [2] 8c d9 [2] a2 d9 [2] 9d c5 }

  condition:
    any of them
}