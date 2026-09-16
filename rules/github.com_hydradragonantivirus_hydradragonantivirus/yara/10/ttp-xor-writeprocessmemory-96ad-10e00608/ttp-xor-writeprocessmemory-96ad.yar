rule TTP_XOR_WriteProcessMemory_96ad {
  strings:
    $key_96ad = { c1 df [2] f3 fd [2] f5 c8 [2] db c8 [2] e4 d4 }

  condition:
    any of them
}