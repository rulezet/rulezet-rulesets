rule TTP_XOR_WriteProcessMemory_b9d6 {
  strings:
    $key_b9d6 = { ee a4 [2] dc 86 [2] da b3 [2] f4 b3 [2] cb af }

  condition:
    any of them
}