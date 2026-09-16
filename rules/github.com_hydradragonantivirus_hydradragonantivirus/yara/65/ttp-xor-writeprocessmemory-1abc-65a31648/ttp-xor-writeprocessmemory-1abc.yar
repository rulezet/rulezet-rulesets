rule TTP_XOR_WriteProcessMemory_1abc {
  strings:
    $key_1abc = { 4d ce [2] 7f ec [2] 79 d9 [2] 57 d9 [2] 68 c5 }

  condition:
    any of them
}