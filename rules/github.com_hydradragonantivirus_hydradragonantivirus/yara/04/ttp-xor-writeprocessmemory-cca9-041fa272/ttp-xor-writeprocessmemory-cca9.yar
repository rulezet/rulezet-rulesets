rule TTP_XOR_WriteProcessMemory_cca9 {
  strings:
    $key_cca9 = { 9b db [2] a9 f9 [2] af cc [2] 81 cc [2] be d0 }

  condition:
    any of them
}