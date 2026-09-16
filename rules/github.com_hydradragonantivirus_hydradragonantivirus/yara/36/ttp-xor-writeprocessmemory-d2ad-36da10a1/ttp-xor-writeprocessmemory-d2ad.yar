rule TTP_XOR_WriteProcessMemory_d2ad {
  strings:
    $key_d2ad = { 85 df [2] b7 fd [2] b1 c8 [2] 9f c8 [2] a0 d4 }

  condition:
    any of them
}