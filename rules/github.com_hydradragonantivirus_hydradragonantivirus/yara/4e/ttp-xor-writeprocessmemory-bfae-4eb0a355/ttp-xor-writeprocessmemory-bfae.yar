rule TTP_XOR_WriteProcessMemory_bfae {
  strings:
    $key_bfae = { e8 dc [2] da fe [2] dc cb [2] f2 cb [2] cd d7 }

  condition:
    any of them
}