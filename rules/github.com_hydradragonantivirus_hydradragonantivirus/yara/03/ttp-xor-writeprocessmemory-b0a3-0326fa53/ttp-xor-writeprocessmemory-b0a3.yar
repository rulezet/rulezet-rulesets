rule TTP_XOR_WriteProcessMemory_b0a3 {
  strings:
    $key_b0a3 = { e7 d1 [2] d5 f3 [2] d3 c6 [2] fd c6 [2] c2 da }

  condition:
    any of them
}