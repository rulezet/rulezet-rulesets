rule TTP_XOR_WriteProcessMemory_b922 {
  strings:
    $key_b922 = { ee 50 [2] dc 72 [2] da 47 [2] f4 47 [2] cb 5b }

  condition:
    any of them
}