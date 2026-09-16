rule TTP_XOR_WriteProcessMemory_8ebc {
  strings:
    $key_8ebc = { d9 ce [2] eb ec [2] ed d9 [2] c3 d9 [2] fc c5 }

  condition:
    any of them
}