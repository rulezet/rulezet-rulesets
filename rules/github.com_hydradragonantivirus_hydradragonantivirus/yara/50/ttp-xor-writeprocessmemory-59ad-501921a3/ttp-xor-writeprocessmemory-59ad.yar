rule TTP_XOR_WriteProcessMemory_59ad {
  strings:
    $key_59ad = { 0e df [2] 3c fd [2] 3a c8 [2] 14 c8 [2] 2b d4 }

  condition:
    any of them
}