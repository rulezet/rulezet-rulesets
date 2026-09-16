rule TTP_XOR_WriteProcessMemory_b9a2 {
  strings:
    $key_b9a2 = { ee d0 [2] dc f2 [2] da c7 [2] f4 c7 [2] cb db }

  condition:
    any of them
}