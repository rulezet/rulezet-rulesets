rule TTP_XOR_WriteProcessMemory_ce30 {
  strings:
    $key_ce30 = { 99 42 [2] ab 60 [2] ad 55 [2] 83 55 [2] bc 49 }

  condition:
    any of them
}