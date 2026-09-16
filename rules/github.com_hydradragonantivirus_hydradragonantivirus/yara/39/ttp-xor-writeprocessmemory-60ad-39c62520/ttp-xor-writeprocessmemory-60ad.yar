rule TTP_XOR_WriteProcessMemory_60ad {
  strings:
    $key_60ad = { 37 df [2] 05 fd [2] 03 c8 [2] 2d c8 [2] 12 d4 }

  condition:
    any of them
}