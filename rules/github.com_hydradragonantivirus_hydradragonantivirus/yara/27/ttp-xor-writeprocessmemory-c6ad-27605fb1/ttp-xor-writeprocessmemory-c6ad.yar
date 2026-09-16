rule TTP_XOR_WriteProcessMemory_c6ad {
  strings:
    $key_c6ad = { 91 df [2] a3 fd [2] a5 c8 [2] 8b c8 [2] b4 d4 }

  condition:
    any of them
}