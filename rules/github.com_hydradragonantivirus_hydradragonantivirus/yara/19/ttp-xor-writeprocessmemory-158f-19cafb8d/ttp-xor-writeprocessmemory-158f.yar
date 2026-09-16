rule TTP_XOR_WriteProcessMemory_158f {
  strings:
    $key_158f = { 42 fd [2] 70 df [2] 76 ea [2] 58 ea [2] 67 f6 }

  condition:
    any of them
}