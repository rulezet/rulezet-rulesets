rule TTP_XOR_WriteProcessMemory_848f {
  strings:
    $key_848f = { d3 fd [2] e1 df [2] e7 ea [2] c9 ea [2] f6 f6 }

  condition:
    any of them
}