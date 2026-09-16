rule TTP_XOR_WriteProcessMemory_648f {
  strings:
    $key_648f = { 33 fd [2] 01 df [2] 07 ea [2] 29 ea [2] 16 f6 }

  condition:
    any of them
}