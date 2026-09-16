rule TTP_XOR_WriteProcessMemory_6598 {
  strings:
    $key_6598 = { 32 ea [2] 00 c8 [2] 06 fd [2] 28 fd [2] 17 e1 }

  condition:
    any of them
}