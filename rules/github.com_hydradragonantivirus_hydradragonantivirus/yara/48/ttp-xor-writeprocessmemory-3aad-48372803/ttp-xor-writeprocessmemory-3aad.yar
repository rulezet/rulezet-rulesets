rule TTP_XOR_WriteProcessMemory_3aad {
  strings:
    $key_3aad = { 6d df [2] 5f fd [2] 59 c8 [2] 77 c8 [2] 48 d4 }

  condition:
    any of them
}