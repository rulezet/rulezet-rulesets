rule TTP_XOR_WriteProcessMemory_b996 {
  strings:
    $key_b996 = { ee e4 [2] dc c6 [2] da f3 [2] f4 f3 [2] cb ef }

  condition:
    any of them
}