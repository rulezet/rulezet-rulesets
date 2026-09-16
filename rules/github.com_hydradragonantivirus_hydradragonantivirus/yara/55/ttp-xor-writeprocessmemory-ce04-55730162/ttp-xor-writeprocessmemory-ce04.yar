rule TTP_XOR_WriteProcessMemory_ce04 {
  strings:
    $key_ce04 = { 99 76 [2] ab 54 [2] ad 61 [2] 83 61 [2] bc 7d }

  condition:
    any of them
}