rule TTP_XOR_WriteProcessMemory_f6ba {
  strings:
    $key_f6ba = { a1 c8 [2] 93 ea [2] 95 df [2] bb df [2] 84 c3 }

  condition:
    any of them
}