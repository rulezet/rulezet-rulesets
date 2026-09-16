rule TTP_XOR_WriteProcessMemory_b9c2 {
  strings:
    $key_b9c2 = { ee b0 [2] dc 92 [2] da a7 [2] f4 a7 [2] cb bb }

  condition:
    any of them
}