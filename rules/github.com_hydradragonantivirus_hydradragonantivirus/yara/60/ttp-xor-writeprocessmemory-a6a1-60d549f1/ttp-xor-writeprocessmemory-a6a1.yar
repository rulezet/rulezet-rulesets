rule TTP_XOR_WriteProcessMemory_a6a1 {
  strings:
    $key_a6a1 = { f1 d3 [2] c3 f1 [2] c5 c4 [2] eb c4 [2] d4 d8 }

  condition:
    any of them
}