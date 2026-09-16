rule TTP_XOR_WriteProcessMemory_b921 {
  strings:
    $key_b921 = { ee 53 [2] dc 71 [2] da 44 [2] f4 44 [2] cb 58 }

  condition:
    any of them
}