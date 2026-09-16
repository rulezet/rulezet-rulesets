rule TTP_XOR_WriteProcessMemory_b931 {
  strings:
    $key_b931 = { ee 43 [2] dc 61 [2] da 54 [2] f4 54 [2] cb 48 }

  condition:
    any of them
}