rule TTP_XOR_WriteProcessMemory_b9d9 {
  strings:
    $key_b9d9 = { ee ab [2] dc 89 [2] da bc [2] f4 bc [2] cb a0 }

  condition:
    any of them
}