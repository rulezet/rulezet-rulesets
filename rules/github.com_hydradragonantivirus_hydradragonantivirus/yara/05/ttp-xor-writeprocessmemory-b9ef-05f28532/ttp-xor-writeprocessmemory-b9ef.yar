rule TTP_XOR_WriteProcessMemory_b9ef {
  strings:
    $key_b9ef = { ee 9d [2] dc bf [2] da 8a [2] f4 8a [2] cb 96 }

  condition:
    any of them
}