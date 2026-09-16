rule TTP_XOR_WriteProcessMemory_b6b2 {
  strings:
    $key_b6b2 = { e1 c0 [2] d3 e2 [2] d5 d7 [2] fb d7 [2] c4 cb }

  condition:
    any of them
}