rule TTP_XOR_WriteProcessMemory_93b1 {
  strings:
    $key_93b1 = { c4 c3 [2] f6 e1 [2] f0 d4 [2] de d4 [2] e1 c8 }

  condition:
    any of them
}