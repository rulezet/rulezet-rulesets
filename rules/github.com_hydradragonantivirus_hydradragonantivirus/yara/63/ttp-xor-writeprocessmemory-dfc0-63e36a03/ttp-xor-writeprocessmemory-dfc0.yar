rule TTP_XOR_WriteProcessMemory_dfc0 {
  strings:
    $key_dfc0 = { 88 b2 [2] ba 90 [2] bc a5 [2] 92 a5 [2] ad b9 }

  condition:
    any of them
}