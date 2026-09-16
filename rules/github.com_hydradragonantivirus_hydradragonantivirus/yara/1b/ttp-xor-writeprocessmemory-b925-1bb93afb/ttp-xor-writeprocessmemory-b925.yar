rule TTP_XOR_WriteProcessMemory_b925 {
  strings:
    $key_b925 = { ee 57 [2] dc 75 [2] da 40 [2] f4 40 [2] cb 5c }

  condition:
    any of them
}