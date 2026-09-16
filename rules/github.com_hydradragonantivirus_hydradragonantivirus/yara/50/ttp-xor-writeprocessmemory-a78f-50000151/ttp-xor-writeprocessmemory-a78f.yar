rule TTP_XOR_WriteProcessMemory_a78f {
  strings:
    $key_a78f = { f0 fd [2] c2 df [2] c4 ea [2] ea ea [2] d5 f6 }

  condition:
    any of them
}