rule TTP_XOR_WriteProcessMemory_4abc {
  strings:
    $key_4abc = { 1d ce [2] 2f ec [2] 29 d9 [2] 07 d9 [2] 38 c5 }

  condition:
    any of them
}