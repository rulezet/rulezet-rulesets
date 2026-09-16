rule TTP_XOR_WriteProcessMemory_8b98 {
  strings:
    $key_8b98 = { dc ea [2] ee c8 [2] e8 fd [2] c6 fd [2] f9 e1 }

  condition:
    any of them
}