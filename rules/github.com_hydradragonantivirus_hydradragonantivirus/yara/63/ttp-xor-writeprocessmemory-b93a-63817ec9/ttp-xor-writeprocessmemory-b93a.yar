rule TTP_XOR_WriteProcessMemory_b93a {
  strings:
    $key_b93a = { ee 48 [2] dc 6a [2] da 5f [2] f4 5f [2] cb 43 }

  condition:
    any of them
}