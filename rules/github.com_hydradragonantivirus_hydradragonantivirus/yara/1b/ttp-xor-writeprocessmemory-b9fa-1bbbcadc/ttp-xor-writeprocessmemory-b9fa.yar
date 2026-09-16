rule TTP_XOR_WriteProcessMemory_b9fa {
  strings:
    $key_b9fa = { ee 88 [2] dc aa [2] da 9f [2] f4 9f [2] cb 83 }

  condition:
    any of them
}