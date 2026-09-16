rule TTP_XOR_WriteProcessMemory_6398 {
  strings:
    $key_6398 = { 34 ea [2] 06 c8 [2] 00 fd [2] 2e fd [2] 11 e1 }

  condition:
    any of them
}