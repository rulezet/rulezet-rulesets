rule TTP_XOR_WriteProcessMemory_f7ba {
  strings:
    $key_f7ba = { a0 c8 [2] 92 ea [2] 94 df [2] ba df [2] 85 c3 }

  condition:
    any of them
}