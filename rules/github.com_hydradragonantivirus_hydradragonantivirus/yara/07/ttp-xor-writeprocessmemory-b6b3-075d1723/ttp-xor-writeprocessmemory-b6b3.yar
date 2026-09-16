rule TTP_XOR_WriteProcessMemory_b6b3 {
  strings:
    $key_b6b3 = { e1 c1 [2] d3 e3 [2] d5 d6 [2] fb d6 [2] c4 ca }

  condition:
    any of them
}