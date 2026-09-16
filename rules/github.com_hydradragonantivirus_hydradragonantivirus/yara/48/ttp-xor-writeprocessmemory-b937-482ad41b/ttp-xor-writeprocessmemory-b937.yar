rule TTP_XOR_WriteProcessMemory_b937 {
  strings:
    $key_b937 = { ee 45 [2] dc 67 [2] da 52 [2] f4 52 [2] cb 4e }

  condition:
    any of them
}