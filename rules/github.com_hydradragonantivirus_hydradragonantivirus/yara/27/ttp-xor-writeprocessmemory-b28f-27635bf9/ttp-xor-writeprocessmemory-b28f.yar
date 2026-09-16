rule TTP_XOR_WriteProcessMemory_b28f {
  strings:
    $key_b28f = { e5 fd [2] d7 df [2] d1 ea [2] ff ea [2] c0 f6 }

  condition:
    any of them
}