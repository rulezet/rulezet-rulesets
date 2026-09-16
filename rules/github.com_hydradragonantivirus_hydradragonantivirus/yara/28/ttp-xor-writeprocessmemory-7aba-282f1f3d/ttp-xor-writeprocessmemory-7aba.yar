rule TTP_XOR_WriteProcessMemory_7aba {
  strings:
    $key_7aba = { 2d c8 [2] 1f ea [2] 19 df [2] 37 df [2] 08 c3 }

  condition:
    any of them
}