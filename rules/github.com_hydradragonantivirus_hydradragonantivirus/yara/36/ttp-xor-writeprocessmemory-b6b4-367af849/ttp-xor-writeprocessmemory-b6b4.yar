rule TTP_XOR_WriteProcessMemory_b6b4 {
  strings:
    $key_b6b4 = { e1 c6 [2] d3 e4 [2] d5 d1 [2] fb d1 [2] c4 cd }

  condition:
    any of them
}