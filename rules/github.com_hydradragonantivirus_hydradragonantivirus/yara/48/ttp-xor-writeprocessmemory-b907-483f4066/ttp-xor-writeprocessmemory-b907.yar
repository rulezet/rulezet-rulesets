rule TTP_XOR_WriteProcessMemory_b907 {
  strings:
    $key_b907 = { ee 75 [2] dc 57 [2] da 62 [2] f4 62 [2] cb 7e }

  condition:
    any of them
}