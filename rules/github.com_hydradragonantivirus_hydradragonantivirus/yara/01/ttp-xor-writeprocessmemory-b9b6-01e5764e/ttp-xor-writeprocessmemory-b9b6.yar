rule TTP_XOR_WriteProcessMemory_b9b6 {
  strings:
    $key_b9b6 = { ee c4 [2] dc e6 [2] da d3 [2] f4 d3 [2] cb cf }

  condition:
    any of them
}