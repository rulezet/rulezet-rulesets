rule TTP_XOR_WriteProcessMemory_e08f {
  strings:
    $key_e08f = { b7 fd [2] 85 df [2] 83 ea [2] ad ea [2] 92 f6 }

  condition:
    any of them
}