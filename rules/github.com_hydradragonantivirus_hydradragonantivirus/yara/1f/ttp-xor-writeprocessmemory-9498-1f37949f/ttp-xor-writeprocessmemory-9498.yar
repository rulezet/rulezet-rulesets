rule TTP_XOR_WriteProcessMemory_9498 {
  strings:
    $key_9498 = { c3 ea [2] f1 c8 [2] f7 fd [2] d9 fd [2] e6 e1 }

  condition:
    any of them
}