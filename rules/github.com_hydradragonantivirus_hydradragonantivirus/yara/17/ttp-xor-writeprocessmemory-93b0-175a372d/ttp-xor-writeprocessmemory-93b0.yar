rule TTP_XOR_WriteProcessMemory_93b0 {
  strings:
    $key_93b0 = { c4 c2 [2] f6 e0 [2] f0 d5 [2] de d5 [2] e1 c9 }

  condition:
    any of them
}