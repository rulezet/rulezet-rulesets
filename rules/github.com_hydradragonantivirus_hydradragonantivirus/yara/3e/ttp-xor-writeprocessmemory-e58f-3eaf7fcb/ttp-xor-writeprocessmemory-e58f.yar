rule TTP_XOR_WriteProcessMemory_e58f {
  strings:
    $key_e58f = { b2 fd [2] 80 df [2] 86 ea [2] a8 ea [2] 97 f6 }

  condition:
    any of them
}