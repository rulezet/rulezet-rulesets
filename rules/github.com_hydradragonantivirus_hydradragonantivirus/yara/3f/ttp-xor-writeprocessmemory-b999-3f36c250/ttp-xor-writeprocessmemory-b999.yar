rule TTP_XOR_WriteProcessMemory_b999 {
  strings:
    $key_b999 = { ee eb [2] dc c9 [2] da fc [2] f4 fc [2] cb e0 }

  condition:
    any of them
}