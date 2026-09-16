rule TTP_XOR_WriteProcessMemory_cabc {
  strings:
    $key_cabc = { 9d ce [2] af ec [2] a9 d9 [2] 87 d9 [2] b8 c5 }

  condition:
    any of them
}