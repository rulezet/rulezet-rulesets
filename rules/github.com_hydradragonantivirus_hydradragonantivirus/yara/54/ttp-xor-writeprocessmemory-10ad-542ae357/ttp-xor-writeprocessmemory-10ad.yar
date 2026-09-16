rule TTP_XOR_WriteProcessMemory_10ad {
  strings:
    $key_10ad = { 47 df [2] 75 fd [2] 73 c8 [2] 5d c8 [2] 62 d4 }

  condition:
    any of them
}