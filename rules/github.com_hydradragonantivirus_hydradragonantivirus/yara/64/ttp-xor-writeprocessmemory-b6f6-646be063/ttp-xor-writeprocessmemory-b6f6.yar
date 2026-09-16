rule TTP_XOR_WriteProcessMemory_b6f6 {
  strings:
    $key_b6f6 = { e1 84 [2] d3 a6 [2] d5 93 [2] fb 93 [2] c4 8f }

  condition:
    any of them
}