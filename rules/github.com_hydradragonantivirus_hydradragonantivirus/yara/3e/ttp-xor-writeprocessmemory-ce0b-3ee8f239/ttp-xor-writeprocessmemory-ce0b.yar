rule TTP_XOR_WriteProcessMemory_ce0b {
  strings:
    $key_ce0b = { 99 79 [2] ab 5b [2] ad 6e [2] 83 6e [2] bc 72 }

  condition:
    any of them
}