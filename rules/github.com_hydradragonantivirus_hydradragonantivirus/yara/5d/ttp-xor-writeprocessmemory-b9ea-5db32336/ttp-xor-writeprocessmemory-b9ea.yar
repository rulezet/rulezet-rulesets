rule TTP_XOR_WriteProcessMemory_b9ea {
  strings:
    $key_b9ea = { ee 98 [2] dc ba [2] da 8f [2] f4 8f [2] cb 93 }

  condition:
    any of them
}