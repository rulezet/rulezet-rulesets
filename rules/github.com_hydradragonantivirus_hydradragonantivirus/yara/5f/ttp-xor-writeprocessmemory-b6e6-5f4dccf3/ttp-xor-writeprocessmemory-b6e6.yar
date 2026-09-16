rule TTP_XOR_WriteProcessMemory_b6e6 {
  strings:
    $key_b6e6 = { e1 94 [2] d3 b6 [2] d5 83 [2] fb 83 [2] c4 9f }

  condition:
    any of them
}