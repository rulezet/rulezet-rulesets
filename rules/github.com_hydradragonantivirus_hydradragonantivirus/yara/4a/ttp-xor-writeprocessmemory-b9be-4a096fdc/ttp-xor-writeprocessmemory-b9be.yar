rule TTP_XOR_WriteProcessMemory_b9be {
  strings:
    $key_b9be = { ee cc [2] dc ee [2] da db [2] f4 db [2] cb c7 }

  condition:
    any of them
}