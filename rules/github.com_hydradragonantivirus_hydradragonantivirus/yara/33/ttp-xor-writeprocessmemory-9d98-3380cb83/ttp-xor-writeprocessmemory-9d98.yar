rule TTP_XOR_WriteProcessMemory_9d98 {
  strings:
    $key_9d98 = { ca ea [2] f8 c8 [2] fe fd [2] d0 fd [2] ef e1 }

  condition:
    any of them
}