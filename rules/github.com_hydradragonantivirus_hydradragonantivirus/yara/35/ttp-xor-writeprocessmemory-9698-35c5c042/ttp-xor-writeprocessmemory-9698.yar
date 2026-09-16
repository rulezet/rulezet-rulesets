rule TTP_XOR_WriteProcessMemory_9698 {
  strings:
    $key_9698 = { c1 ea [2] f3 c8 [2] f5 fd [2] db fd [2] e4 e1 }

  condition:
    any of them
}