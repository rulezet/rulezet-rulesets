rule TTP_XOR_WriteProcessMemory_8198 {
  strings:
    $key_8198 = { d6 ea [2] e4 c8 [2] e2 fd [2] cc fd [2] f3 e1 }

  condition:
    any of them
}