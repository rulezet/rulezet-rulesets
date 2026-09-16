rule TTP_XOR_WriteProcessMemory_80ad {
  strings:
    $key_80ad = { d7 df [2] e5 fd [2] e3 c8 [2] cd c8 [2] f2 d4 }

  condition:
    any of them
}