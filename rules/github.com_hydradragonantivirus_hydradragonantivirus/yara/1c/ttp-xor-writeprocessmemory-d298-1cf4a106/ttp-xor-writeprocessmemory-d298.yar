rule TTP_XOR_WriteProcessMemory_d298 {
  strings:
    $key_d298 = { 85 ea [2] b7 c8 [2] b1 fd [2] 9f fd [2] a0 e1 }

  condition:
    any of them
}