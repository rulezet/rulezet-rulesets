rule TTP_XOR_WriteProcessMemory_8cba {
  strings:
    $key_8cba = { db c8 [2] e9 ea [2] ef df [2] c1 df [2] fe c3 }

  condition:
    any of them
}