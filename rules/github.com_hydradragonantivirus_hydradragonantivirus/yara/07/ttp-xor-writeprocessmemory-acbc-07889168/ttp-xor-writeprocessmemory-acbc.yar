rule TTP_XOR_WriteProcessMemory_acbc {
  strings:
    $key_acbc = { fb ce [2] c9 ec [2] cf d9 [2] e1 d9 [2] de c5 }

  condition:
    any of them
}