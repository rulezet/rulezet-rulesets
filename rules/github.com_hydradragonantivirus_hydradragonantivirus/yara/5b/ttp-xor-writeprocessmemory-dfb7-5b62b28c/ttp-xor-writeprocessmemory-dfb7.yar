rule TTP_XOR_WriteProcessMemory_dfb7 {
  strings:
    $key_dfb7 = { 88 c5 [2] ba e7 [2] bc d2 [2] 92 d2 [2] ad ce }

  condition:
    any of them
}