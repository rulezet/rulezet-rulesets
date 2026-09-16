rule TTP_XOR_WriteProcessMemory_a7ba {
  strings:
    $key_a7ba = { f0 c8 [2] c2 ea [2] c4 df [2] ea df [2] d5 c3 }

  condition:
    any of them
}