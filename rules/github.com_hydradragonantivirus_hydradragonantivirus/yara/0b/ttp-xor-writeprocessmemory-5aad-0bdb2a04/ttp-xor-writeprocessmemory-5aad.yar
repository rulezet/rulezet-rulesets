rule TTP_XOR_WriteProcessMemory_5aad {
  strings:
    $key_5aad = { 0d df [2] 3f fd [2] 39 c8 [2] 17 c8 [2] 28 d4 }

  condition:
    any of them
}