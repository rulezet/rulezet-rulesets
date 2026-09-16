rule TTP_XOR_WriteProcessMemory_b94a {
  strings:
    $key_b94a = { ee 38 [2] dc 1a [2] da 2f [2] f4 2f [2] cb 33 }

  condition:
    any of them
}