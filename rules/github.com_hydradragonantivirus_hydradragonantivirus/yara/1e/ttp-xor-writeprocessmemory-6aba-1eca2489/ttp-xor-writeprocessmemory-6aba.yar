rule TTP_XOR_WriteProcessMemory_6aba {
  strings:
    $key_6aba = { 3d c8 [2] 0f ea [2] 09 df [2] 27 df [2] 18 c3 }

  condition:
    any of them
}