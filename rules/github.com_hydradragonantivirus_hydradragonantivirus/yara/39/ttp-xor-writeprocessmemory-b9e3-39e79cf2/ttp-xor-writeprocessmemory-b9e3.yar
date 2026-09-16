rule TTP_XOR_WriteProcessMemory_b9e3 {
  strings:
    $key_b9e3 = { ee 91 [2] dc b3 [2] da 86 [2] f4 86 [2] cb 9a }

  condition:
    any of them
}