rule TTP_XOR_WriteProcessMemory_b9b4 {
  strings:
    $key_b9b4 = { ee c6 [2] dc e4 [2] da d1 [2] f4 d1 [2] cb cd }

  condition:
    any of them
}