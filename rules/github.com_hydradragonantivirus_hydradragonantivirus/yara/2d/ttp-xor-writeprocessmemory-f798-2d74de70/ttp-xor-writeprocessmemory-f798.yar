rule TTP_XOR_WriteProcessMemory_f798 {
  strings:
    $key_f798 = { a0 ea [2] 92 c8 [2] 94 fd [2] ba fd [2] 85 e1 }

  condition:
    any of them
}