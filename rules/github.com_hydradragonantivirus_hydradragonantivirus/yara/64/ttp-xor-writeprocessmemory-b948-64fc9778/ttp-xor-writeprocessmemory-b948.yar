rule TTP_XOR_WriteProcessMemory_b948 {
  strings:
    $key_b948 = { ee 3a [2] dc 18 [2] da 2d [2] f4 2d [2] cb 31 }

  condition:
    any of them
}