rule TTP_XOR_WriteProcessMemory_b9c1 {
  strings:
    $key_b9c1 = { ee b3 [2] dc 91 [2] da a4 [2] f4 a4 [2] cb b8 }

  condition:
    any of them
}