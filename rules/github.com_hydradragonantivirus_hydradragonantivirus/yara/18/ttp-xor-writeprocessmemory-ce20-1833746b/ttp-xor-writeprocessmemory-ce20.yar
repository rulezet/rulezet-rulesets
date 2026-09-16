rule TTP_XOR_WriteProcessMemory_ce20 {
  strings:
    $key_ce20 = { 99 52 [2] ab 70 [2] ad 45 [2] 83 45 [2] bc 59 }

  condition:
    any of them
}