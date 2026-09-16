rule TTP_XOR_WriteProcessMemory_d8ad {
  strings:
    $key_d8ad = { 8f df [2] bd fd [2] bb c8 [2] 95 c8 [2] aa d4 }

  condition:
    any of them
}