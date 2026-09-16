rule TTP_XOR_WriteProcessMemory_87ad {
  strings:
    $key_87ad = { d0 df [2] e2 fd [2] e4 c8 [2] ca c8 [2] f5 d4 }

  condition:
    any of them
}