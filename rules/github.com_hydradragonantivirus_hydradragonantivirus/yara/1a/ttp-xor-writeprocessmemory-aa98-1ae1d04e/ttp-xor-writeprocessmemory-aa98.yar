rule TTP_XOR_WriteProcessMemory_aa98 {
  strings:
    $key_aa98 = { fd ea [2] cf c8 [2] c9 fd [2] e7 fd [2] d8 e1 }

  condition:
    any of them
}