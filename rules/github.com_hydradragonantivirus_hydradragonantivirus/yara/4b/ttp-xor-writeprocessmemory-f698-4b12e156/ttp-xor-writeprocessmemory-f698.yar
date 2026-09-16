rule TTP_XOR_WriteProcessMemory_f698 {
  strings:
    $key_f698 = { a1 ea [2] 93 c8 [2] 95 fd [2] bb fd [2] 84 e1 }

  condition:
    any of them
}