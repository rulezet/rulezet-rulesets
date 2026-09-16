rule TTP_XOR_WriteProcessMemory_09ad {
  strings:
    $key_09ad = { 5e df [2] 6c fd [2] 6a c8 [2] 44 c8 [2] 7b d4 }

  condition:
    any of them
}