rule TTP_XOR_WriteProcessMemory_a798 {
  strings:
    $key_a798 = { f0 ea [2] c2 c8 [2] c4 fd [2] ea fd [2] d5 e1 }

  condition:
    any of them
}