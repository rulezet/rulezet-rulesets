rule TTP_XOR_WriteProcessMemory_b0e6 {
  strings:
    $key_b0e6 = { e7 94 [2] d5 b6 [2] d3 83 [2] fd 83 [2] c2 9f }

  condition:
    any of them
}