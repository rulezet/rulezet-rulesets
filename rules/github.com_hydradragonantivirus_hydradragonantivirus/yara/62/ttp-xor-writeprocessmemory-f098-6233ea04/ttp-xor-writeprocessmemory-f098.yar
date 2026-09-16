rule TTP_XOR_WriteProcessMemory_f098 {
  strings:
    $key_f098 = { a7 ea [2] 95 c8 [2] 93 fd [2] bd fd [2] 82 e1 }

  condition:
    any of them
}