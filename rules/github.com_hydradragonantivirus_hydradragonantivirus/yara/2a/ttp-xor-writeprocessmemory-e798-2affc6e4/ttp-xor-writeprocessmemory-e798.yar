rule TTP_XOR_WriteProcessMemory_e798 {
  strings:
    $key_e798 = { b0 ea [2] 82 c8 [2] 84 fd [2] aa fd [2] 95 e1 }

  condition:
    any of them
}