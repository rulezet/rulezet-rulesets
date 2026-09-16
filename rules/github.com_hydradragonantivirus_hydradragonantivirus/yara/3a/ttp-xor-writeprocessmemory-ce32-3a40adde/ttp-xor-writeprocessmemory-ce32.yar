rule TTP_XOR_WriteProcessMemory_ce32 {
  strings:
    $key_ce32 = { 99 40 [2] ab 62 [2] ad 57 [2] 83 57 [2] bc 4b }

  condition:
    any of them
}