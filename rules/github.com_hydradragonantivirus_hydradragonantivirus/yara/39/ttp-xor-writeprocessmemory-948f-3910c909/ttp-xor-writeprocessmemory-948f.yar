rule TTP_XOR_WriteProcessMemory_948f {
  strings:
    $key_948f = { c3 fd [2] f1 df [2] f7 ea [2] d9 ea [2] e6 f6 }

  condition:
    any of them
}