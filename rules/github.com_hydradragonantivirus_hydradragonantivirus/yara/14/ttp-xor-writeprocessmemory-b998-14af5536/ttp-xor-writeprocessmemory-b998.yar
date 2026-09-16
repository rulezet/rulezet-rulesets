rule TTP_XOR_WriteProcessMemory_b998 {
  strings:
    $key_b998 = { ee ea [2] dc c8 [2] da fd [2] f4 fd [2] cb e1 }

  condition:
    any of them
}