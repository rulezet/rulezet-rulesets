rule TTP_XOR_WriteProcessMemory_b980 {
  strings:
    $key_b980 = { ee f2 [2] dc d0 [2] da e5 [2] f4 e5 [2] cb f9 }

  condition:
    any of them
}