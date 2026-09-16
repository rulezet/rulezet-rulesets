rule TTP_XOR_WriteProcessMemory_9298 {
  strings:
    $key_9298 = { c5 ea [2] f7 c8 [2] f1 fd [2] df fd [2] e0 e1 }

  condition:
    any of them
}