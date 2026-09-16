rule TTP_XOR_WriteProcessMemory_968f {
  strings:
    $key_968f = { c1 fd [2] f3 df [2] f5 ea [2] db ea [2] e4 f6 }

  condition:
    any of them
}