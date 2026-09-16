rule TTP_XOR_WriteProcessMemory_93a1 {
  strings:
    $key_93a1 = { c4 d3 [2] f6 f1 [2] f0 c4 [2] de c4 [2] e1 d8 }

  condition:
    any of them
}