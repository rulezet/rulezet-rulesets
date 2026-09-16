rule TTP_XOR_WriteProcessMemory_debc {
  strings:
    $key_debc = { 89 ce [2] bb ec [2] bd d9 [2] 93 d9 [2] ac c5 }

  condition:
    any of them
}