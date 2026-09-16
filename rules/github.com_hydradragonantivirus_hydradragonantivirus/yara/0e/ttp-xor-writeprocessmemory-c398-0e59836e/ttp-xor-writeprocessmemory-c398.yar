rule TTP_XOR_WriteProcessMemory_c398 {
  strings:
    $key_c398 = { 94 ea [2] a6 c8 [2] a0 fd [2] 8e fd [2] b1 e1 }

  condition:
    any of them
}