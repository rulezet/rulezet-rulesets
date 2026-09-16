rule TTP_XOR_WriteProcessMemory_e9b0 {
  strings:
    $key_e9b0 = { be c2 [2] 8c e0 [2] 8a d5 [2] a4 d5 [2] 9b c9 }

  condition:
    any of them
}