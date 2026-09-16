rule TTP_XOR_WriteProcessMemory_b9c3 {
  strings:
    $key_b9c3 = { ee b1 [2] dc 93 [2] da a6 [2] f4 a6 [2] cb ba }

  condition:
    any of them
}