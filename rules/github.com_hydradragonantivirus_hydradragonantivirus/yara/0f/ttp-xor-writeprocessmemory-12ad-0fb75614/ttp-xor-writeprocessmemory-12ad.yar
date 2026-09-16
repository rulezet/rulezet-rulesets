rule TTP_XOR_WriteProcessMemory_12ad {
  strings:
    $key_12ad = { 45 df [2] 77 fd [2] 71 c8 [2] 5f c8 [2] 60 d4 }

  condition:
    any of them
}