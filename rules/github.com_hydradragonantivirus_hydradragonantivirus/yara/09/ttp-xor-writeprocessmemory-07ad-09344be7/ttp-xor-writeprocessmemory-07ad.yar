rule TTP_XOR_WriteProcessMemory_07ad {
  strings:
    $key_07ad = { 50 df [2] 62 fd [2] 64 c8 [2] 4a c8 [2] 75 d4 }

  condition:
    any of them
}