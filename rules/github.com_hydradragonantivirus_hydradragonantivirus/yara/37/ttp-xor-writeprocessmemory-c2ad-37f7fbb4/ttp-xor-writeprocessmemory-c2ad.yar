rule TTP_XOR_WriteProcessMemory_c2ad {
  strings:
    $key_c2ad = { 95 df [2] a7 fd [2] a1 c8 [2] 8f c8 [2] b0 d4 }

  condition:
    any of them
}