rule TTP_XOR_WriteProcessMemory_b971 {
  strings:
    $key_b971 = { ee 03 [2] dc 21 [2] da 14 [2] f4 14 [2] cb 08 }

  condition:
    any of them
}