rule TTP_XOR_WriteProcessMemory_f0a1 {
  strings:
    $key_f0a1 = { a7 d3 [2] 95 f1 [2] 93 c4 [2] bd c4 [2] 82 d8 }

  condition:
    any of them
}