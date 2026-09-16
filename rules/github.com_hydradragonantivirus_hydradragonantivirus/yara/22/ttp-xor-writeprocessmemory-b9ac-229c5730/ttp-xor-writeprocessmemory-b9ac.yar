rule TTP_XOR_WriteProcessMemory_b9ac {
  strings:
    $key_b9ac = { ee de [2] dc fc [2] da c9 [2] f4 c9 [2] cb d5 }

  condition:
    any of them
}