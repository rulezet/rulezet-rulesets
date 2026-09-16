rule TTP_XOR_WriteProcessMemory_9798 {
  strings:
    $key_9798 = { c0 ea [2] f2 c8 [2] f4 fd [2] da fd [2] e5 e1 }

  condition:
    any of them
}