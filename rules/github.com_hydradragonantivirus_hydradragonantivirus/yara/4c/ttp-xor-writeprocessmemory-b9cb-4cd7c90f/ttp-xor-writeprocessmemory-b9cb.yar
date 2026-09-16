rule TTP_XOR_WriteProcessMemory_b9cb {
  strings:
    $key_b9cb = { ee b9 [2] dc 9b [2] da ae [2] f4 ae [2] cb b2 }

  condition:
    any of them
}