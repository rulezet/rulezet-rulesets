rule TTP_XOR_WriteProcessMemory_85ad {
  strings:
    $key_85ad = { d2 df [2] e0 fd [2] e6 c8 [2] c8 c8 [2] f7 d4 }

  condition:
    any of them
}