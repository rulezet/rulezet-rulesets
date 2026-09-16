rule TTP_XOR_WriteProcessMemory_1298 {
  strings:
    $key_1298 = { 45 ea [2] 77 c8 [2] 71 fd [2] 5f fd [2] 60 e1 }

  condition:
    any of them
}