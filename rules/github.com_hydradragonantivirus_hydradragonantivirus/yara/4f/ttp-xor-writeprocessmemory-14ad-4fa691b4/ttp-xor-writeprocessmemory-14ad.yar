rule TTP_XOR_WriteProcessMemory_14ad {
  strings:
    $key_14ad = { 43 df [2] 71 fd [2] 77 c8 [2] 59 c8 [2] 66 d4 }

  condition:
    any of them
}