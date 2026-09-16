rule TTP_XOR_WriteProcessMemory_d598 {
  strings:
    $key_d598 = { 82 ea [2] b0 c8 [2] b6 fd [2] 98 fd [2] a7 e1 }

  condition:
    any of them
}