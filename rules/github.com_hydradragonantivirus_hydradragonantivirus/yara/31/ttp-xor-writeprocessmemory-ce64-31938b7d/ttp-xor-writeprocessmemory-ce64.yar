rule TTP_XOR_WriteProcessMemory_ce64 {
  strings:
    $key_ce64 = { 99 16 [2] ab 34 [2] ad 01 [2] 83 01 [2] bc 1d }

  condition:
    any of them
}