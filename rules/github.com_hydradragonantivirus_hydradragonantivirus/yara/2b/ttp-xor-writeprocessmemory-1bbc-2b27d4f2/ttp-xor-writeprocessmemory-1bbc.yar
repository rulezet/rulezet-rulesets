rule TTP_XOR_WriteProcessMemory_1bbc {
  strings:
    $key_1bbc = { 4c ce [2] 7e ec [2] 78 d9 [2] 56 d9 [2] 69 c5 }

  condition:
    any of them
}