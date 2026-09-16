rule TTP_XOR_WriteProcessMemory_b9c7 {
  strings:
    $key_b9c7 = { ee b5 [2] dc 97 [2] da a2 [2] f4 a2 [2] cb be }

  condition:
    any of them
}