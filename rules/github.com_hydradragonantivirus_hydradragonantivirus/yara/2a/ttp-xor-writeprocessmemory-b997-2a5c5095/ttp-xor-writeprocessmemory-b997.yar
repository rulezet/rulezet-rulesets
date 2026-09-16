rule TTP_XOR_WriteProcessMemory_b997 {
  strings:
    $key_b997 = { ee e5 [2] dc c7 [2] da f2 [2] f4 f2 [2] cb ee }

  condition:
    any of them
}