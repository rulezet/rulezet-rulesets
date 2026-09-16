rule TTP_XOR_WriteProcessMemory_b5ad {
  strings:
    $key_b5ad = { e2 df [2] d0 fd [2] d6 c8 [2] f8 c8 [2] c7 d4 }

  condition:
    any of them
}