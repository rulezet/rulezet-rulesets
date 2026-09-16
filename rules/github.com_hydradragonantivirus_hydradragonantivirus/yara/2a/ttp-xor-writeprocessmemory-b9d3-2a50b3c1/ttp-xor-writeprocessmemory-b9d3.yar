rule TTP_XOR_WriteProcessMemory_b9d3 {
  strings:
    $key_b9d3 = { ee a1 [2] dc 83 [2] da b6 [2] f4 b6 [2] cb aa }

  condition:
    any of them
}