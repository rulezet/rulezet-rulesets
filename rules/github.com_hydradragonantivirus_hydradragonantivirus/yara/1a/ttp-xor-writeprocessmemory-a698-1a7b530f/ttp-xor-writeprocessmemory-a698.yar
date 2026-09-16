rule TTP_XOR_WriteProcessMemory_a698 {
  strings:
    $key_a698 = { f1 ea [2] c3 c8 [2] c5 fd [2] eb fd [2] d4 e1 }

  condition:
    any of them
}