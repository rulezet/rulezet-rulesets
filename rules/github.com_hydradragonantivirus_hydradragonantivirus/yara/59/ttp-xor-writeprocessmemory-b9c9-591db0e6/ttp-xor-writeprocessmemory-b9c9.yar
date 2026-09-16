rule TTP_XOR_WriteProcessMemory_b9c9 {
  strings:
    $key_b9c9 = { ee bb [2] dc 99 [2] da ac [2] f4 ac [2] cb b0 }

  condition:
    any of them
}