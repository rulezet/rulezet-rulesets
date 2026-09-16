rule TTP_XOR_WriteProcessMemory_f18f {
  strings:
    $key_f18f = { a6 fd [2] 94 df [2] 92 ea [2] bc ea [2] 83 f6 }

  condition:
    any of them
}