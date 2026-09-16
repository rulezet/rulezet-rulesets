rule TTP_XOR_WriteProcessMemory_39ad {
  strings:
    $key_39ad = { 6e df [2] 5c fd [2] 5a c8 [2] 74 c8 [2] 4b d4 }

  condition:
    any of them
}