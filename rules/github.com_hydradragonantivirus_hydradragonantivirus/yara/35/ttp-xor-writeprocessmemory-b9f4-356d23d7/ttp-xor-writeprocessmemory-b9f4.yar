rule TTP_XOR_WriteProcessMemory_b9f4 {
  strings:
    $key_b9f4 = { ee 86 [2] dc a4 [2] da 91 [2] f4 91 [2] cb 8d }

  condition:
    any of them
}