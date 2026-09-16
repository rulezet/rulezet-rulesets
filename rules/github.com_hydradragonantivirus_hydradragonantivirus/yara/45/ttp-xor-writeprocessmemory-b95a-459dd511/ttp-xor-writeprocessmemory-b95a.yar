rule TTP_XOR_WriteProcessMemory_b95a {
  strings:
    $key_b95a = { ee 28 [2] dc 0a [2] da 3f [2] f4 3f [2] cb 23 }

  condition:
    any of them
}