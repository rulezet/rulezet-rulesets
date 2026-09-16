rule TTP_XOR_WriteProcessMemory_458f {
  strings:
    $key_458f = { 12 fd [2] 20 df [2] 26 ea [2] 08 ea [2] 37 f6 }

  condition:
    any of them
}