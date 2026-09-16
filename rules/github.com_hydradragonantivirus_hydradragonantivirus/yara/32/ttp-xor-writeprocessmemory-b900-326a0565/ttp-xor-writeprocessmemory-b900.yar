rule TTP_XOR_WriteProcessMemory_b900 {
  strings:
    $key_b900 = { ee 72 [2] dc 50 [2] da 65 [2] f4 65 [2] cb 79 }

  condition:
    any of them
}