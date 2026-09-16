rule TTP_XOR_WriteProcessMemory_5abc {
  strings:
    $key_5abc = { 0d ce [2] 3f ec [2] 39 d9 [2] 17 d9 [2] 28 c5 }

  condition:
    any of them
}