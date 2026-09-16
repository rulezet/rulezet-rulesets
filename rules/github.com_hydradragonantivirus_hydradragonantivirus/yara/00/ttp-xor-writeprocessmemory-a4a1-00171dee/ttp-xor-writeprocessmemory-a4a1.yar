rule TTP_XOR_WriteProcessMemory_a4a1 {
  strings:
    $key_a4a1 = { f3 d3 [2] c1 f1 [2] c7 c4 [2] e9 c4 [2] d6 d8 }

  condition:
    any of them
}