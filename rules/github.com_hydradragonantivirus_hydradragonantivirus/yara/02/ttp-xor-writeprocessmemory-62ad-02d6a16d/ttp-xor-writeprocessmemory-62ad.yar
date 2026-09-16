rule TTP_XOR_WriteProcessMemory_62ad {
  strings:
    $key_62ad = { 35 df [2] 07 fd [2] 01 c8 [2] 2f c8 [2] 10 d4 }

  condition:
    any of them
}