rule TTP_XOR_WriteProcessMemory_b9d0 {
  strings:
    $key_b9d0 = { ee a2 [2] dc 80 [2] da b5 [2] f4 b5 [2] cb a9 }

  condition:
    any of them
}