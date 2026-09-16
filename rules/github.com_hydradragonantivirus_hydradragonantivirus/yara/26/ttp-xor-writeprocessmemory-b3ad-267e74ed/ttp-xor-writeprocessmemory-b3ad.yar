rule TTP_XOR_WriteProcessMemory_b3ad {
  strings:
    $key_b3ad = { e4 df [2] d6 fd [2] d0 c8 [2] fe c8 [2] c1 d4 }

  condition:
    any of them
}