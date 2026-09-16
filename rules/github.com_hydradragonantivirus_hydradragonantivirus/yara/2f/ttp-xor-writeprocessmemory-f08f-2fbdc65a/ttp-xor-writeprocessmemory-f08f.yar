rule TTP_XOR_WriteProcessMemory_f08f {
  strings:
    $key_f08f = { a7 fd [2] 95 df [2] 93 ea [2] bd ea [2] 82 f6 }

  condition:
    any of them
}