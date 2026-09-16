rule TTP_XOR_WriteProcessMemory_65ad {
  strings:
    $key_65ad = { 32 df [2] 00 fd [2] 06 c8 [2] 28 c8 [2] 17 d4 }

  condition:
    any of them
}