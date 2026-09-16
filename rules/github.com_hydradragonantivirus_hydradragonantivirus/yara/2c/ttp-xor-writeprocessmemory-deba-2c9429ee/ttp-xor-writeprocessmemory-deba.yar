rule TTP_XOR_WriteProcessMemory_deba {
  strings:
    $key_deba = { 89 c8 [2] bb ea [2] bd df [2] 93 df [2] ac c3 }

  condition:
    any of them
}