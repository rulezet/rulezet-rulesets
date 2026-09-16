rule TTP_XOR_WriteProcessMemory_ce7b {
  strings:
    $key_ce7b = { 99 09 [2] ab 2b [2] ad 1e [2] 83 1e [2] bc 02 }

  condition:
    any of them
}