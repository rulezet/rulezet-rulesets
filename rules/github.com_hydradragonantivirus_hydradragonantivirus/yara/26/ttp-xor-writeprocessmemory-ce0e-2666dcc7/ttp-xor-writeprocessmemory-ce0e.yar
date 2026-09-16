rule TTP_XOR_WriteProcessMemory_ce0e {
  strings:
    $key_ce0e = { 99 7c [2] ab 5e [2] ad 6b [2] 83 6b [2] bc 77 }

  condition:
    any of them
}