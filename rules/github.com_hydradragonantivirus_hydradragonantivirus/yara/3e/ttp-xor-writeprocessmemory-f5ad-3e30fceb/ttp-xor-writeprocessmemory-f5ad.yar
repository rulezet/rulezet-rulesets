rule TTP_XOR_WriteProcessMemory_f5ad {
  strings:
    $key_f5ad = { a2 df [2] 90 fd [2] 96 c8 [2] b8 c8 [2] 87 d4 }

  condition:
    any of them
}