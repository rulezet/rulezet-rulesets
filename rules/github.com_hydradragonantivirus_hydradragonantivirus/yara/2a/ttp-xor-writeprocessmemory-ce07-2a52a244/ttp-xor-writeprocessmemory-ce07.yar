rule TTP_XOR_WriteProcessMemory_ce07 {
  strings:
    $key_ce07 = { 99 75 [2] ab 57 [2] ad 62 [2] 83 62 [2] bc 7e }

  condition:
    any of them
}