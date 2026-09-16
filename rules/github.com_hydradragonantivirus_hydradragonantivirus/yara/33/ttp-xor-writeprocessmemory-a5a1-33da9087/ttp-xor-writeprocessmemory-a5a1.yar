rule TTP_XOR_WriteProcessMemory_a5a1 {
  strings:
    $key_a5a1 = { f2 d3 [2] c0 f1 [2] c6 c4 [2] e8 c4 [2] d7 d8 }

  condition:
    any of them
}