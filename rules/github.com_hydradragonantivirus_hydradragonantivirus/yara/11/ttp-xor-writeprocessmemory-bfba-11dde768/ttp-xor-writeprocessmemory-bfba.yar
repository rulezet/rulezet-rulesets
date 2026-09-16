rule TTP_XOR_WriteProcessMemory_bfba {
  strings:
    $key_bfba = { e8 c8 [2] da ea [2] dc df [2] f2 df [2] cd c3 }

  condition:
    any of them
}