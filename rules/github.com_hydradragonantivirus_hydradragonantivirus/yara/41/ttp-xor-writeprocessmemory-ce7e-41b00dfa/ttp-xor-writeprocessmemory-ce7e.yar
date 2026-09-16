rule TTP_XOR_WriteProcessMemory_ce7e {
  strings:
    $key_ce7e = { 99 0c [2] ab 2e [2] ad 1b [2] 83 1b [2] bc 07 }

  condition:
    any of them
}