rule TTP_XOR_WriteProcessMemory_738f {
  strings:
    $key_738f = { 24 fd [2] 16 df [2] 10 ea [2] 3e ea [2] 01 f6 }

  condition:
    any of them
}