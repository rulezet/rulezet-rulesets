rule TTP_XOR_WriteProcessMemory_b9db {
  strings:
    $key_b9db = { ee a9 [2] dc 8b [2] da be [2] f4 be [2] cb a2 }

  condition:
    any of them
}