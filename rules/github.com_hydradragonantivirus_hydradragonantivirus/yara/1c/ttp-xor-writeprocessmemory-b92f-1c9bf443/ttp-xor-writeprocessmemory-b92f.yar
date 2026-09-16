rule TTP_XOR_WriteProcessMemory_b92f {
  strings:
    $key_b92f = { ee 5d [2] dc 7f [2] da 4a [2] f4 4a [2] cb 56 }

  condition:
    any of them
}