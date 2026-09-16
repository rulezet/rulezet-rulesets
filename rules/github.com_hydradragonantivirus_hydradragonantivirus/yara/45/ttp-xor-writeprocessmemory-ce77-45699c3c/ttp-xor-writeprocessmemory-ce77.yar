rule TTP_XOR_WriteProcessMemory_ce77 {
  strings:
    $key_ce77 = { 99 05 [2] ab 27 [2] ad 12 [2] 83 12 [2] bc 0e }

  condition:
    any of them
}