rule TTP_XOR_WriteProcessMemory_7798 {
  strings:
    $key_7798 = { 20 ea [2] 12 c8 [2] 14 fd [2] 3a fd [2] 05 e1 }

  condition:
    any of them
}