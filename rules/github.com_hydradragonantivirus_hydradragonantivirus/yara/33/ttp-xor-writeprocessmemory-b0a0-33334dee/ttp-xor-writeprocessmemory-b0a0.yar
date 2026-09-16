rule TTP_XOR_WriteProcessMemory_b0a0 {
  strings:
    $key_b0a0 = { e7 d2 [2] d5 f0 [2] d3 c5 [2] fd c5 [2] c2 d9 }

  condition:
    any of them
}