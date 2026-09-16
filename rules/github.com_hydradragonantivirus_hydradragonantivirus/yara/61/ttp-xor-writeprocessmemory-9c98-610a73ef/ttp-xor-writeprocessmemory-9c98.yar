rule TTP_XOR_WriteProcessMemory_9c98 {
  strings:
    $key_9c98 = { cb ea [2] f9 c8 [2] ff fd [2] d1 fd [2] ee e1 }

  condition:
    any of them
}