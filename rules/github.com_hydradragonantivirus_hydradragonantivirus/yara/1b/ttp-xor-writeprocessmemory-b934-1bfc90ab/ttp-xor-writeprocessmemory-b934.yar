rule TTP_XOR_WriteProcessMemory_b934 {
  strings:
    $key_b934 = { ee 46 [2] dc 64 [2] da 51 [2] f4 51 [2] cb 4d }

  condition:
    any of them
}