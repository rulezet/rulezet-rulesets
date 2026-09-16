rule TTP_XOR_WriteProcessMemory_b0a6 {
  strings:
    $key_b0a6 = { e7 d4 [2] d5 f6 [2] d3 c3 [2] fd c3 [2] c2 df }

  condition:
    any of them
}