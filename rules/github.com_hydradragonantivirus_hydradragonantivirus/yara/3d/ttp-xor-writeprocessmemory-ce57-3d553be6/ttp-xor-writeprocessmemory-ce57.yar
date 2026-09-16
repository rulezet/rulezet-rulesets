rule TTP_XOR_WriteProcessMemory_ce57 {
  strings:
    $key_ce57 = { 99 25 [2] ab 07 [2] ad 32 [2] 83 32 [2] bc 2e }

  condition:
    any of them
}