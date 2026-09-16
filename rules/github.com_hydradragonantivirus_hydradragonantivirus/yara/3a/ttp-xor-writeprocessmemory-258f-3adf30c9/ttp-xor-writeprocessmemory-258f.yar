rule TTP_XOR_WriteProcessMemory_258f {
  strings:
    $key_258f = { 72 fd [2] 40 df [2] 46 ea [2] 68 ea [2] 57 f6 }

  condition:
    any of them
}