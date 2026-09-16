rule TTP_XOR_WriteProcessMemory_b990 {
  strings:
    $key_b990 = { ee e2 [2] dc c0 [2] da f5 [2] f4 f5 [2] cb e9 }

  condition:
    any of them
}