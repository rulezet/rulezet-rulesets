rule TTP_XOR_WriteProcessMemory_b9e4 {
  strings:
    $key_b9e4 = { ee 96 [2] dc b4 [2] da 81 [2] f4 81 [2] cb 9d }

  condition:
    any of them
}