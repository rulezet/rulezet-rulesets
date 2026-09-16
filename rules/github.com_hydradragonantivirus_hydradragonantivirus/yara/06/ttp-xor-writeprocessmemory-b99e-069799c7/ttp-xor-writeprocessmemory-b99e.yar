rule TTP_XOR_WriteProcessMemory_b99e {
  strings:
    $key_b99e = { ee ec [2] dc ce [2] da fb [2] f4 fb [2] cb e7 }

  condition:
    any of them
}