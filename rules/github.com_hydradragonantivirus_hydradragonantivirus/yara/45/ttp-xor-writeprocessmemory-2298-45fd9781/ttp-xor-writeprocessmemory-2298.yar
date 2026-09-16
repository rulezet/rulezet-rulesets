rule TTP_XOR_WriteProcessMemory_2298 {
  strings:
    $key_2298 = { 75 ea [2] 47 c8 [2] 41 fd [2] 6f fd [2] 50 e1 }

  condition:
    any of them
}