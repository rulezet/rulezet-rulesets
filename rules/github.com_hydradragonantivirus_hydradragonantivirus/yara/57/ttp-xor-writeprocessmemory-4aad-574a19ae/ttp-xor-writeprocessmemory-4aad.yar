rule TTP_XOR_WriteProcessMemory_4aad {
  strings:
    $key_4aad = { 1d df [2] 2f fd [2] 29 c8 [2] 07 c8 [2] 38 d4 }

  condition:
    any of them
}