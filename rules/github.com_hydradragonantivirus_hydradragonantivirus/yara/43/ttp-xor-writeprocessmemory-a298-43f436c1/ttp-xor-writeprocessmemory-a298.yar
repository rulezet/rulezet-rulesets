rule TTP_XOR_WriteProcessMemory_a298 {
  strings:
    $key_a298 = { f5 ea [2] c7 c8 [2] c1 fd [2] ef fd [2] d0 e1 }

  condition:
    any of them
}