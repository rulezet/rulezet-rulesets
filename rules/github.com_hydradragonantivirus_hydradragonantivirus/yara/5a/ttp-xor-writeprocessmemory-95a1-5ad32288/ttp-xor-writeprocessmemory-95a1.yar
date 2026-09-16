rule TTP_XOR_WriteProcessMemory_95a1 {
  strings:
    $key_95a1 = { c2 d3 [2] f0 f1 [2] f6 c4 [2] d8 c4 [2] e7 d8 }

  condition:
    any of them
}