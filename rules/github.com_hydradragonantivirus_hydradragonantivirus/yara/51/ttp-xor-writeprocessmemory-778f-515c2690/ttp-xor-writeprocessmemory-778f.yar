rule TTP_XOR_WriteProcessMemory_778f {
  strings:
    $key_778f = { 20 fd [2] 12 df [2] 14 ea [2] 3a ea [2] 05 f6 }

  condition:
    any of them
}