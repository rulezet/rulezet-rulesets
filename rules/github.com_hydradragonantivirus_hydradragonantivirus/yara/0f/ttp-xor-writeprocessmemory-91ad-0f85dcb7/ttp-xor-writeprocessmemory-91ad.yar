rule TTP_XOR_WriteProcessMemory_91ad {
  strings:
    $key_91ad = { c6 df [2] f4 fd [2] f2 c8 [2] dc c8 [2] e3 d4 }

  condition:
    any of them
}