rule TTP_XOR_WriteProcessMemory_ccb1 {
  strings:
    $key_ccb1 = { 9b c3 [2] a9 e1 [2] af d4 [2] 81 d4 [2] be c8 }

  condition:
    any of them
}