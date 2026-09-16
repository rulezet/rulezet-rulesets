rule TTP_XOR_WriteProcessMemory_b93d {
  strings:
    $key_b93d = { ee 4f [2] dc 6d [2] da 58 [2] f4 58 [2] cb 44 }

  condition:
    any of them
}