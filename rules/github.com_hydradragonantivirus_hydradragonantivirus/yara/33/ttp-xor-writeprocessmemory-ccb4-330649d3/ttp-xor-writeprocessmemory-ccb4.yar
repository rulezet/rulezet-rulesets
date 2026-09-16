rule TTP_XOR_WriteProcessMemory_ccb4 {
  strings:
    $key_ccb4 = { 9b c6 [2] a9 e4 [2] af d1 [2] 81 d1 [2] be cd }

  condition:
    any of them
}