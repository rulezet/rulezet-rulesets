rule TTP_XOR_WriteProcessMemory_b92a {
  strings:
    $key_b92a = { ee 58 [2] dc 7a [2] da 4f [2] f4 4f [2] cb 53 }

  condition:
    any of them
}