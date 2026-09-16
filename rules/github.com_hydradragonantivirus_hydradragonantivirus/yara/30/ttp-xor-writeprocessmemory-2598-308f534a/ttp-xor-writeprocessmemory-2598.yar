rule TTP_XOR_WriteProcessMemory_2598 {
  strings:
    $key_2598 = { 72 ea [2] 40 c8 [2] 46 fd [2] 68 fd [2] 57 e1 }

  condition:
    any of them
}