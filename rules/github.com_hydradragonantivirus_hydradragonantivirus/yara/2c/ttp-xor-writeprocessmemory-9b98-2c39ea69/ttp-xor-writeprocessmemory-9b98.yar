rule TTP_XOR_WriteProcessMemory_9b98 {
  strings:
    $key_9b98 = { cc ea [2] fe c8 [2] f8 fd [2] d6 fd [2] e9 e1 }

  condition:
    any of them
}