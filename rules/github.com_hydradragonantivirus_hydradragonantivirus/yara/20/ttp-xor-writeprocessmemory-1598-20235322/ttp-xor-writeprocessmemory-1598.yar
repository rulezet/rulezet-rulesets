rule TTP_XOR_WriteProcessMemory_1598 {
  strings:
    $key_1598 = { 42 ea [2] 70 c8 [2] 76 fd [2] 58 fd [2] 67 e1 }

  condition:
    any of them
}