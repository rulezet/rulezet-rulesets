rule TTP_XOR_WriteProcessMemory_b9bc {
  strings:
    $key_b9bc = { ee ce [2] dc ec [2] da d9 [2] f4 d9 [2] cb c5 }

  condition:
    any of them
}