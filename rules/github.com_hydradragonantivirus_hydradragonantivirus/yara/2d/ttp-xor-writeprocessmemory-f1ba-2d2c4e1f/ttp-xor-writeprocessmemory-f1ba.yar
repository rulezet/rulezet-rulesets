rule TTP_XOR_WriteProcessMemory_f1ba {
  strings:
    $key_f1ba = { a6 c8 [2] 94 ea [2] 92 df [2] bc df [2] 83 c3 }

  condition:
    any of them
}