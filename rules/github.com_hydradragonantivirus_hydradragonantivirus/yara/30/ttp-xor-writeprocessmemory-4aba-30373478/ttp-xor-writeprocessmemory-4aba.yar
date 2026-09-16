rule TTP_XOR_WriteProcessMemory_4aba {
  strings:
    $key_4aba = { 1d c8 [2] 2f ea [2] 29 df [2] 07 df [2] 38 c3 }

  condition:
    any of them
}