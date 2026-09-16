rule TTP_XOR_WriteProcessMemory_c3ad {
  strings:
    $key_c3ad = { 94 df [2] a6 fd [2] a0 c8 [2] 8e c8 [2] b1 d4 }

  condition:
    any of them
}