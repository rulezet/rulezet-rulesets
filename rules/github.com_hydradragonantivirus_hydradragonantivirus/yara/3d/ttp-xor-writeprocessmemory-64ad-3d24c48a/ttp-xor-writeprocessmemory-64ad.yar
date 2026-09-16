rule TTP_XOR_WriteProcessMemory_64ad {
  strings:
    $key_64ad = { 33 df [2] 01 fd [2] 07 c8 [2] 29 c8 [2] 16 d4 }

  condition:
    any of them
}