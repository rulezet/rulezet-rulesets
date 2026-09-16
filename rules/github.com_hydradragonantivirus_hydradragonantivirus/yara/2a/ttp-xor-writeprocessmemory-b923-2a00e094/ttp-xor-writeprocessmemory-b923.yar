rule TTP_XOR_WriteProcessMemory_b923 {
  strings:
    $key_b923 = { ee 51 [2] dc 73 [2] da 46 [2] f4 46 [2] cb 5a }

  condition:
    any of them
}