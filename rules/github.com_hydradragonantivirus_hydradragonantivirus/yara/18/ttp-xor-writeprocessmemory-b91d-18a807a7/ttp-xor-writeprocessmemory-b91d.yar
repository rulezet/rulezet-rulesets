rule TTP_XOR_WriteProcessMemory_b91d {
  strings:
    $key_b91d = { ee 6f [2] dc 4d [2] da 78 [2] f4 78 [2] cb 64 }

  condition:
    any of them
}