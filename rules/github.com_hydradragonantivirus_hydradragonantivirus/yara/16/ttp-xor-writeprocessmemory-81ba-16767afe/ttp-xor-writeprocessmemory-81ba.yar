rule TTP_XOR_WriteProcessMemory_81ba {
  strings:
    $key_81ba = { d6 c8 [2] e4 ea [2] e2 df [2] cc df [2] f3 c3 }

  condition:
    any of them
}