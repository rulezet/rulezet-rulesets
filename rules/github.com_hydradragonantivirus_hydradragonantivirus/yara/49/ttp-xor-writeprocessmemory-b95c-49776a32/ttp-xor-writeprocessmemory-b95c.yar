rule TTP_XOR_WriteProcessMemory_b95c {
  strings:
    $key_b95c = { ee 2e [2] dc 0c [2] da 39 [2] f4 39 [2] cb 25 }

  condition:
    any of them
}