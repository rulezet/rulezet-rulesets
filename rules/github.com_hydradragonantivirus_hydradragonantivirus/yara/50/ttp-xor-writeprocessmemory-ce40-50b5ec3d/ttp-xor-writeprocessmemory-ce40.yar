rule TTP_XOR_WriteProcessMemory_ce40 {
  strings:
    $key_ce40 = { 99 32 [2] ab 10 [2] ad 25 [2] 83 25 [2] bc 39 }

  condition:
    any of them
}