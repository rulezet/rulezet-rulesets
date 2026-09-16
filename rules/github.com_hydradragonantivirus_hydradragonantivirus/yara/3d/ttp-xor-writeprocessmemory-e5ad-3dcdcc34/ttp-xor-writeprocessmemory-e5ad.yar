rule TTP_XOR_WriteProcessMemory_e5ad {
  strings:
    $key_e5ad = { b2 df [2] 80 fd [2] 86 c8 [2] a8 c8 [2] 97 d4 }

  condition:
    any of them
}