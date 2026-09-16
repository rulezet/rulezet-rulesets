rule TTP_XOR_WriteProcessMemory_ce2c {
  strings:
    $key_ce2c = { 99 5e [2] ab 7c [2] ad 49 [2] 83 49 [2] bc 55 }

  condition:
    any of them
}