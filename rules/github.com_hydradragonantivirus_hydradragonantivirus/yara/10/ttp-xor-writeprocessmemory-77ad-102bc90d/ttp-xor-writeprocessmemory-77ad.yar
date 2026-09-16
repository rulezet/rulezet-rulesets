rule TTP_XOR_WriteProcessMemory_77ad {
  strings:
    $key_77ad = { 20 df [2] 12 fd [2] 14 c8 [2] 3a c8 [2] 05 d4 }

  condition:
    any of them
}