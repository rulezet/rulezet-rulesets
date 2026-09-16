rule TTP_XOR_WriteProcessMemory_4798 {
  strings:
    $key_4798 = { 10 ea [2] 22 c8 [2] 24 fd [2] 0a fd [2] 35 e1 }

  condition:
    any of them
}