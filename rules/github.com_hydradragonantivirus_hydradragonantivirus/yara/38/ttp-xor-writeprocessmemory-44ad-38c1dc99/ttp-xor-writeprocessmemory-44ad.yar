rule TTP_XOR_WriteProcessMemory_44ad {
  strings:
    $key_44ad = { 13 df [2] 21 fd [2] 27 c8 [2] 09 c8 [2] 36 d4 }

  condition:
    any of them
}