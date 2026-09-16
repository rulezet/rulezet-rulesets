rule TTP_XOR_WriteProcessMemory_0598 {
  strings:
    $key_0598 = { 52 ea [2] 60 c8 [2] 66 fd [2] 48 fd [2] 77 e1 }

  condition:
    any of them
}