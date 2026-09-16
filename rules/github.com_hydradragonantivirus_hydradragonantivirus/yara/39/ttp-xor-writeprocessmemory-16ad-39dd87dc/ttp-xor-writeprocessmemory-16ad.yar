rule TTP_XOR_WriteProcessMemory_16ad {
  strings:
    $key_16ad = { 41 df [2] 73 fd [2] 75 c8 [2] 5b c8 [2] 64 d4 }

  condition:
    any of them
}