rule TTP_XOR_WriteProcessMemory_b58f {
  strings:
    $key_b58f = { e2 fd [2] d0 df [2] d6 ea [2] f8 ea [2] c7 f6 }

  condition:
    any of them
}