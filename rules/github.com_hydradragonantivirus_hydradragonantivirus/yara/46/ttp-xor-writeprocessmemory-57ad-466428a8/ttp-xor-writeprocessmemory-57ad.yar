rule TTP_XOR_WriteProcessMemory_57ad {
  strings:
    $key_57ad = { 00 df [2] 32 fd [2] 34 c8 [2] 1a c8 [2] 25 d4 }

  condition:
    any of them
}