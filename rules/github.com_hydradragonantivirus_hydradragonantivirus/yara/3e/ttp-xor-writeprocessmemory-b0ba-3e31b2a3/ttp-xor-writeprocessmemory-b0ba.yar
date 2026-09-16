rule TTP_XOR_WriteProcessMemory_b0ba {
  strings:
    $key_b0ba = { e7 c8 [2] d5 ea [2] d3 df [2] fd df [2] c2 c3 }

  condition:
    any of them
}