rule TTP_XOR_WriteProcessMemory_a68f {
  strings:
    $key_a68f = { f1 fd [2] c3 df [2] c5 ea [2] eb ea [2] d4 f6 }

  condition:
    any of them
}