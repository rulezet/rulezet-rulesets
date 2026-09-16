rule TTP_XOR_WriteProcessMemory_34ad {
  strings:
    $key_34ad = { 63 df [2] 51 fd [2] 57 c8 [2] 79 c8 [2] 46 d4 }

  condition:
    any of them
}