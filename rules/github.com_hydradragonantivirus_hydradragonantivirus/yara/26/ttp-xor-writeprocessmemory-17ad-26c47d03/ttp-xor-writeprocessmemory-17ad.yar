rule TTP_XOR_WriteProcessMemory_17ad {
  strings:
    $key_17ad = { 40 df [2] 72 fd [2] 74 c8 [2] 5a c8 [2] 65 d4 }

  condition:
    any of them
}