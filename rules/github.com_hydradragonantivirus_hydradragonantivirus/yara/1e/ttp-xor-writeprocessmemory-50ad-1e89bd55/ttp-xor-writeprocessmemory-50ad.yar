rule TTP_XOR_WriteProcessMemory_50ad {
  strings:
    $key_50ad = { 07 df [2] 35 fd [2] 33 c8 [2] 1d c8 [2] 22 d4 }

  condition:
    any of them
}