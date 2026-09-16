rule TTP_XOR_WriteProcessMemory_ce6e {
  strings:
    $key_ce6e = { 99 1c [2] ab 3e [2] ad 0b [2] 83 0b [2] bc 17 }

  condition:
    any of them
}