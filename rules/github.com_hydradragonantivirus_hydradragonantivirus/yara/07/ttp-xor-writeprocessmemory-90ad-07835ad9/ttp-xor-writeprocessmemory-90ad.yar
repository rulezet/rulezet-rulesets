rule TTP_XOR_WriteProcessMemory_90ad {
  strings:
    $key_90ad = { c7 df [2] f5 fd [2] f3 c8 [2] dd c8 [2] e2 d4 }

  condition:
    any of them
}