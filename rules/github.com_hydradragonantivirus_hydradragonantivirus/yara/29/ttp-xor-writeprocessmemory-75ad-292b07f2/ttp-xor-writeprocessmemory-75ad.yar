rule TTP_XOR_WriteProcessMemory_75ad {
  strings:
    $key_75ad = { 22 df [2] 10 fd [2] 16 c8 [2] 38 c8 [2] 07 d4 }

  condition:
    any of them
}