rule TTP_XOR_WriteProcessMemory_19ad {
  strings:
    $key_19ad = { 4e df [2] 7c fd [2] 7a c8 [2] 54 c8 [2] 6b d4 }

  condition:
    any of them
}