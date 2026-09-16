rule TTP_XOR_WriteProcessMemory_b6b0 {
  strings:
    $key_b6b0 = { e1 c2 [2] d3 e0 [2] d5 d5 [2] fb d5 [2] c4 c9 }

  condition:
    any of them
}