rule TTP_XOR_WriteProcessMemory_3bbc {
  strings:
    $key_3bbc = { 6c ce [2] 5e ec [2] 58 d9 [2] 76 d9 [2] 49 c5 }

  condition:
    any of them
}