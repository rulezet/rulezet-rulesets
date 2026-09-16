rule TTP_XOR_WriteProcessMemory_fabc {
  strings:
    $key_fabc = { ad ce [2] 9f ec [2] 99 d9 [2] b7 d9 [2] 88 c5 }

  condition:
    any of them
}