rule TTP_XOR_WriteProcessMemory_b95d {
  strings:
    $key_b95d = { ee 2f [2] dc 0d [2] da 38 [2] f4 38 [2] cb 24 }

  condition:
    any of them
}