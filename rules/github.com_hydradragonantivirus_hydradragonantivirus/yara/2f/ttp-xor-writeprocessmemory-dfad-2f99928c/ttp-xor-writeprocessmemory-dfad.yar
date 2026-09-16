rule TTP_XOR_WriteProcessMemory_dfad {
  strings:
    $key_dfad = { 88 df [2] ba fd [2] bc c8 [2] 92 c8 [2] ad d4 }

  condition:
    any of them
}