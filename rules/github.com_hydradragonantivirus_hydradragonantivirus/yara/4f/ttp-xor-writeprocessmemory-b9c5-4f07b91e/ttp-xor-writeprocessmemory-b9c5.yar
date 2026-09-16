rule TTP_XOR_WriteProcessMemory_b9c5 {
  strings:
    $key_b9c5 = { ee b7 [2] dc 95 [2] da a0 [2] f4 a0 [2] cb bc }

  condition:
    any of them
}