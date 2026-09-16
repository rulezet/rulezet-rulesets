rule TTP_XOR_WriteProcessMemory_b90f {
  strings:
    $key_b90f = { ee 7d [2] dc 5f [2] da 6a [2] f4 6a [2] cb 76 }

  condition:
    any of them
}