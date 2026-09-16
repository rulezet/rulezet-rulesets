rule TTP_XOR_WriteProcessMemory_b3ba {
  strings:
    $key_b3ba = { e4 c8 [2] d6 ea [2] d0 df [2] fe df [2] c1 c3 }

  condition:
    any of them
}