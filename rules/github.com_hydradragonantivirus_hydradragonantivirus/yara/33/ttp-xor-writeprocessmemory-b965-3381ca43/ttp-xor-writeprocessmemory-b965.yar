rule TTP_XOR_WriteProcessMemory_b965 {
  strings:
    $key_b965 = { ee 17 [2] dc 35 [2] da 00 [2] f4 00 [2] cb 1c }

  condition:
    any of them
}