rule TTP_XOR_WriteProcessMemory_b910 {
  strings:
    $key_b910 = { ee 62 [2] dc 40 [2] da 75 [2] f4 75 [2] cb 69 }

  condition:
    any of them
}