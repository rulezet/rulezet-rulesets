rule TTP_XOR_WriteProcessMemory_b94d {
  strings:
    $key_b94d = { ee 3f [2] dc 1d [2] da 28 [2] f4 28 [2] cb 34 }

  condition:
    any of them
}