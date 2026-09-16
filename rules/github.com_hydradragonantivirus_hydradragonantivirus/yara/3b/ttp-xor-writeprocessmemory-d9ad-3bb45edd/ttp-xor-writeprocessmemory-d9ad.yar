rule TTP_XOR_WriteProcessMemory_d9ad {
  strings:
    $key_d9ad = { 8e df [2] bc fd [2] ba c8 [2] 94 c8 [2] ab d4 }

  condition:
    any of them
}