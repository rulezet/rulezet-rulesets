rule TTP_XOR_WriteProcessMemory_b9ad {
  strings:
    $key_b9ad = { ee df [2] dc fd [2] da c8 [2] f4 c8 [2] cb d4 }

  condition:
    any of them
}