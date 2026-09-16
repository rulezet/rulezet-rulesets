rule TTP_XOR_WriteProcessMemory_b9d7 {
  strings:
    $key_b9d7 = { ee a5 [2] dc 87 [2] da b2 [2] f4 b2 [2] cb ae }

  condition:
    any of them
}