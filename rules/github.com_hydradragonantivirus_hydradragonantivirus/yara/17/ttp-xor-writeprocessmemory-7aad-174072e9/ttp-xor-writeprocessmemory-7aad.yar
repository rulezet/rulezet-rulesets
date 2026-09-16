rule TTP_XOR_WriteProcessMemory_7aad {
  strings:
    $key_7aad = { 2d df [2] 1f fd [2] 19 c8 [2] 37 c8 [2] 08 d4 }

  condition:
    any of them
}