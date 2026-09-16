rule TTP_XOR_WriteProcessMemory_ce43 {
  strings:
    $key_ce43 = { 99 31 [2] ab 13 [2] ad 26 [2] 83 26 [2] bc 3a }

  condition:
    any of them
}