rule TTP_XOR_WriteProcessMemory_b598 {
  strings:
    $key_b598 = { e2 ea [2] d0 c8 [2] d6 fd [2] f8 fd [2] c7 e1 }

  condition:
    any of them
}