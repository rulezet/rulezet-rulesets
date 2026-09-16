rule TTP_XOR_WriteProcessMemory_1498 {
  strings:
    $key_1498 = { 43 ea [2] 71 c8 [2] 77 fd [2] 59 fd [2] 66 e1 }

  condition:
    any of them
}