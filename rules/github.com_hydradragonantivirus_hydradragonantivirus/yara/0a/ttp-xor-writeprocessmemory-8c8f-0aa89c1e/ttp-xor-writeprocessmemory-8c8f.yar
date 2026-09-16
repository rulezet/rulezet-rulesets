rule TTP_XOR_WriteProcessMemory_8c8f {
  strings:
    $key_8c8f = { db fd [2] e9 df [2] ef ea [2] c1 ea [2] fe f6 }

  condition:
    any of them
}