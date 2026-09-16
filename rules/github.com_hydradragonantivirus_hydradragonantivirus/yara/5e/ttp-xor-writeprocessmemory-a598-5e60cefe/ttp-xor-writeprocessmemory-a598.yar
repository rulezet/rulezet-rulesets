rule TTP_XOR_WriteProcessMemory_a598 {
  strings:
    $key_a598 = { f2 ea [2] c0 c8 [2] c6 fd [2] e8 fd [2] d7 e1 }

  condition:
    any of them
}