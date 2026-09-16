rule TTP_XOR_WriteProcessMemory_2bbc {
  strings:
    $key_2bbc = { 7c ce [2] 4e ec [2] 48 d9 [2] 66 d9 [2] 59 c5 }

  condition:
    any of them
}