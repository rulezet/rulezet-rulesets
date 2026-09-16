rule TTP_XOR_WriteProcessMemory_55ad {
  strings:
    $key_55ad = { 02 df [2] 30 fd [2] 36 c8 [2] 18 c8 [2] 27 d4 }

  condition:
    any of them
}