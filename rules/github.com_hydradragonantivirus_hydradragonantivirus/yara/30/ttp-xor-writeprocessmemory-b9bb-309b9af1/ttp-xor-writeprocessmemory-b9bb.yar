rule TTP_XOR_WriteProcessMemory_b9bb {
  strings:
    $key_b9bb = { ee c9 [2] dc eb [2] da de [2] f4 de [2] cb c2 }

  condition:
    any of them
}