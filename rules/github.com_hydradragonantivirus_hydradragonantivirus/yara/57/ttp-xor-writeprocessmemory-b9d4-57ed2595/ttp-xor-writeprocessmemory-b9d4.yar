rule TTP_XOR_WriteProcessMemory_b9d4 {
  strings:
    $key_b9d4 = { ee a6 [2] dc 84 [2] da b1 [2] f4 b1 [2] cb ad }

  condition:
    any of them
}