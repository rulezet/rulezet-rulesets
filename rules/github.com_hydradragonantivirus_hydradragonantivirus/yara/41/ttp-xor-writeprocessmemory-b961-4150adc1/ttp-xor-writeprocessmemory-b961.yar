rule TTP_XOR_WriteProcessMemory_b961 {
  strings:
    $key_b961 = { ee 13 [2] dc 31 [2] da 04 [2] f4 04 [2] cb 18 }

  condition:
    any of them
}