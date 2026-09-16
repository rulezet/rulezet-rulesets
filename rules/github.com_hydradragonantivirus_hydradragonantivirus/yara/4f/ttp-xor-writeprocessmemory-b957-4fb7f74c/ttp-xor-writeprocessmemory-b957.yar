rule TTP_XOR_WriteProcessMemory_b957 {
  strings:
    $key_b957 = { ee 25 [2] dc 07 [2] da 32 [2] f4 32 [2] cb 2e }

  condition:
    any of them
}