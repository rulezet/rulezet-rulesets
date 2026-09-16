rule TTP_XOR_WriteProcessMemory_b9cc {
  strings:
    $key_b9cc = { ee be [2] dc 9c [2] da a9 [2] f4 a9 [2] cb b5 }

  condition:
    any of them
}