rule TTP_XOR_WriteProcessMemory_d3b2 {
  strings:
    $key_d3b2 = { 84 c0 [2] b6 e2 [2] b0 d7 [2] 9e d7 [2] a1 cb }

  condition:
    any of them
}