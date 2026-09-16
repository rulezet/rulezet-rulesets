rule TTP_XOR_WriteProcessMemory_0aba {
  strings:
    $key_0aba = { 5d c8 [2] 6f ea [2] 69 df [2] 47 df [2] 78 c3 }

  condition:
    any of them
}