rule TTP_XOR_WriteProcessMemory_b949 {
  strings:
    $key_b949 = { ee 3b [2] dc 19 [2] da 2c [2] f4 2c [2] cb 30 }

  condition:
    any of them
}