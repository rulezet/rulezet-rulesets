rule TTP_XOR_WriteProcessMemory_b9d5 {
  strings:
    $key_b9d5 = { ee a7 [2] dc 85 [2] da b0 [2] f4 b0 [2] cb ac }

  condition:
    any of them
}