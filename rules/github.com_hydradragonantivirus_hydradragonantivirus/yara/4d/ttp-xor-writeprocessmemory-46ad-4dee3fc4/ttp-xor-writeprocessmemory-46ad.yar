rule TTP_XOR_WriteProcessMemory_46ad {
  strings:
    $key_46ad = { 11 df [2] 23 fd [2] 25 c8 [2] 0b c8 [2] 34 d4 }

  condition:
    any of them
}