rule TTP_XOR_WriteProcessMemory_ce0c {
  strings:
    $key_ce0c = { 99 7e [2] ab 5c [2] ad 69 [2] 83 69 [2] bc 75 }

  condition:
    any of them
}