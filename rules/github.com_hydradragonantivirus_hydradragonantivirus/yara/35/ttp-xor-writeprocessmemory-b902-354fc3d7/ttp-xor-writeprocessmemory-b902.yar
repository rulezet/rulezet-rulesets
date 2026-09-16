rule TTP_XOR_WriteProcessMemory_b902 {
  strings:
    $key_b902 = { ee 70 [2] dc 52 [2] da 67 [2] f4 67 [2] cb 7b }

  condition:
    any of them
}