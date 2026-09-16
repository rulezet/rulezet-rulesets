rule TTP_XOR_WriteProcessMemory_b929 {
  strings:
    $key_b929 = { ee 5b [2] dc 79 [2] da 4c [2] f4 4c [2] cb 50 }

  condition:
    any of them
}