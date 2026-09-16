rule TTP_XOR_WriteProcessMemory_858f {
  strings:
    $key_858f = { d2 fd [2] e0 df [2] e6 ea [2] c8 ea [2] f7 f6 }

  condition:
    any of them
}