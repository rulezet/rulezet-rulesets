rule TTP_XOR_WriteProcessMemory_ce34 {
  strings:
    $key_ce34 = { 99 46 [2] ab 64 [2] ad 51 [2] 83 51 [2] bc 4d }

  condition:
    any of them
}