rule TTP_XOR_WriteProcessMemory_b9ed {
  strings:
    $key_b9ed = { ee 9f [2] dc bd [2] da 88 [2] f4 88 [2] cb 94 }

  condition:
    any of them
}