rule TTP_XOR_WriteProcessMemory_b6d5 {
  strings:
    $key_b6d5 = { e1 a7 [2] d3 85 [2] d5 b0 [2] fb b0 [2] c4 ac }

  condition:
    any of them
}