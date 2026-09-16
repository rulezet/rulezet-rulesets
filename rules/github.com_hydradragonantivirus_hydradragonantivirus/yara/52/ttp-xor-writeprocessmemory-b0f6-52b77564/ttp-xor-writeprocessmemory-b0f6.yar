rule TTP_XOR_WriteProcessMemory_b0f6 {
  strings:
    $key_b0f6 = { e7 84 [2] d5 a6 [2] d3 93 [2] fd 93 [2] c2 8f }

  condition:
    any of them
}