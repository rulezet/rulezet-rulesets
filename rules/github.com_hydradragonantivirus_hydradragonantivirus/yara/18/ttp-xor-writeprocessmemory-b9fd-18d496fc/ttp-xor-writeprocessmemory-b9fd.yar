rule TTP_XOR_WriteProcessMemory_b9fd {
  strings:
    $key_b9fd = { ee 8f [2] dc ad [2] da 98 [2] f4 98 [2] cb 84 }

  condition:
    any of them
}