rule TTP_XOR_WriteProcessMemory_ec8f {
  strings:
    $key_ec8f = { bb fd [2] 89 df [2] 8f ea [2] a1 ea [2] 9e f6 }

  condition:
    any of them
}