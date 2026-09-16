rule TTP_XOR_WriteProcessMemory_b9b9 {
  strings:
    $key_b9b9 = { ee cb [2] dc e9 [2] da dc [2] f4 dc [2] cb c0 }

  condition:
    any of them
}