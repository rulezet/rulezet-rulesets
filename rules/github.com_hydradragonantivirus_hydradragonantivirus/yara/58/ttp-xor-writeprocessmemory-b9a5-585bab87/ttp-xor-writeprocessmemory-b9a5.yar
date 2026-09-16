rule TTP_XOR_WriteProcessMemory_b9a5 {
  strings:
    $key_b9a5 = { ee d7 [2] dc f5 [2] da c0 [2] f4 c0 [2] cb dc }

  condition:
    any of them
}