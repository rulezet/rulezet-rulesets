rule TTP_XOR_WriteProcessMemory_2aba {
  strings:
    $key_2aba = { 7d c8 [2] 4f ea [2] 49 df [2] 67 df [2] 58 c3 }

  condition:
    any of them
}