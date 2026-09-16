rule TTP_XOR_WriteProcessMemory_ce41 {
  strings:
    $key_ce41 = { 99 33 [2] ab 11 [2] ad 24 [2] 83 24 [2] bc 38 }

  condition:
    any of them
}