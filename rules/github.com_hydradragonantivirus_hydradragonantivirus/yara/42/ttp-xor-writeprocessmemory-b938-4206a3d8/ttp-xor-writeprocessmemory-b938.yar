rule TTP_XOR_WriteProcessMemory_b938 {
  strings:
    $key_b938 = { ee 4a [2] dc 68 [2] da 5d [2] f4 5d [2] cb 41 }

  condition:
    any of them
}