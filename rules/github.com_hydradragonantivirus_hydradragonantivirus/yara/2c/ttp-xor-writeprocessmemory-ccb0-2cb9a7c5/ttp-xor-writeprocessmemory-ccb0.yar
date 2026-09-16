rule TTP_XOR_WriteProcessMemory_ccb0 {
  strings:
    $key_ccb0 = { 9b c2 [2] a9 e0 [2] af d5 [2] 81 d5 [2] be c9 }

  condition:
    any of them
}