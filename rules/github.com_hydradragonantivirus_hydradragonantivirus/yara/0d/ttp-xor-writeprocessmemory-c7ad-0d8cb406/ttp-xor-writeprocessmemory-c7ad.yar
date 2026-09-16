rule TTP_XOR_WriteProcessMemory_c7ad {
  strings:
    $key_c7ad = { 90 df [2] a2 fd [2] a4 c8 [2] 8a c8 [2] b5 d4 }

  condition:
    any of them
}