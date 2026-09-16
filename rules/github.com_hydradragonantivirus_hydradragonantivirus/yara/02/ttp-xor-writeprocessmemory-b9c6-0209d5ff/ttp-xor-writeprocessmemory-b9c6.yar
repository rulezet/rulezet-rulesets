rule TTP_XOR_WriteProcessMemory_b9c6 {
  strings:
    $key_b9c6 = { ee b4 [2] dc 96 [2] da a3 [2] f4 a3 [2] cb bf }

  condition:
    any of them
}