rule TTP_XOR_WriteProcessMemory_b91e {
  strings:
    $key_b91e = { ee 6c [2] dc 4e [2] da 7b [2] f4 7b [2] cb 67 }

  condition:
    any of them
}