rule TTP_XOR_WriteProcessMemory_758f {
  strings:
    $key_758f = { 22 fd [2] 10 df [2] 16 ea [2] 38 ea [2] 07 f6 }

  condition:
    any of them
}