rule TTP_XOR_WriteProcessMemory_b681 {
  strings:
    $key_b681 = { e1 f3 [2] d3 d1 [2] d5 e4 [2] fb e4 [2] c4 f8 }

  condition:
    any of them
}