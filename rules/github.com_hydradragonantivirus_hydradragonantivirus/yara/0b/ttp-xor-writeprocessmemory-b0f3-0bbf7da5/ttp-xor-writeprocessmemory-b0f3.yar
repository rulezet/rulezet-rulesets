rule TTP_XOR_WriteProcessMemory_b0f3 {
  strings:
    $key_b0f3 = { e7 81 [2] d5 a3 [2] d3 96 [2] fd 96 [2] c2 8a }

  condition:
    any of them
}