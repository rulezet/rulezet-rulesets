rule TTP_XOR_WriteProcessMemory_05ad {
  strings:
    $key_05ad = { 52 df [2] 60 fd [2] 66 c8 [2] 48 c8 [2] 77 d4 }

  condition:
    any of them
}