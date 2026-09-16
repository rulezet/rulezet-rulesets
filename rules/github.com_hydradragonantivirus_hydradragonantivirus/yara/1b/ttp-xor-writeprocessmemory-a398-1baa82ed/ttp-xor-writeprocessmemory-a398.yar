rule TTP_XOR_WriteProcessMemory_a398 {
  strings:
    $key_a398 = { f4 ea [2] c6 c8 [2] c0 fd [2] ee fd [2] d1 e1 }

  condition:
    any of them
}