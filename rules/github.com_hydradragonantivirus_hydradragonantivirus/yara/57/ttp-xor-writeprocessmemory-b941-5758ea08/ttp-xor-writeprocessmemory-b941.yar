rule TTP_XOR_WriteProcessMemory_b941 {
  strings:
    $key_b941 = { ee 33 [2] dc 11 [2] da 24 [2] f4 24 [2] cb 38 }

  condition:
    any of them
}