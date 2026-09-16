rule TTP_XOR_WriteProcessMemory_b9b3 {
  strings:
    $key_b9b3 = { ee c1 [2] dc e3 [2] da d6 [2] f4 d6 [2] cb ca }

  condition:
    any of them
}