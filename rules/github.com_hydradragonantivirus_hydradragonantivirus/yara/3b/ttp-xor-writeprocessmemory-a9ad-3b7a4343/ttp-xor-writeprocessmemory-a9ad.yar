rule TTP_XOR_WriteProcessMemory_a9ad {
  strings:
    $key_a9ad = { fe df [2] cc fd [2] ca c8 [2] e4 c8 [2] db d4 }

  condition:
    any of them
}