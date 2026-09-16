rule TTP_XOR_WriteProcessMemory_b968 {
  strings:
    $key_b968 = { ee 1a [2] dc 38 [2] da 0d [2] f4 0d [2] cb 11 }

  condition:
    any of them
}