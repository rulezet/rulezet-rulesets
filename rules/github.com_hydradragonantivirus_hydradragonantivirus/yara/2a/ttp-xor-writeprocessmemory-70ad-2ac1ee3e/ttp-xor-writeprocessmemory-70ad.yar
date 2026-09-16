rule TTP_XOR_WriteProcessMemory_70ad {
  strings:
    $key_70ad = { 27 df [2] 15 fd [2] 13 c8 [2] 3d c8 [2] 02 d4 }

  condition:
    any of them
}