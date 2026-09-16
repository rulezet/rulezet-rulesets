rule TTP_XOR_WriteProcessMemory_b969 {
  strings:
    $key_b969 = { ee 1b [2] dc 39 [2] da 0c [2] f4 0c [2] cb 10 }

  condition:
    any of them
}