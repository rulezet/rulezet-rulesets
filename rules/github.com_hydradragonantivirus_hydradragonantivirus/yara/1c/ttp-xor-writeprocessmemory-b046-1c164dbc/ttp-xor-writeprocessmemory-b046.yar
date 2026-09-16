rule TTP_XOR_WriteProcessMemory_b046 {
  strings:
    $key_b046 = { e7 34 [2] d5 16 [2] d3 23 [2] fd 23 [2] c2 3f }

  condition:
    any of them
}