rule TTP_XOR_WriteProcessMemory_b9dc {
  strings:
    $key_b9dc = { ee ae [2] dc 8c [2] da b9 [2] f4 b9 [2] cb a5 }

  condition:
    any of them
}