rule TTP_XOR_WriteProcessMemory_ce5d {
  strings:
    $key_ce5d = { 99 2f [2] ab 0d [2] ad 38 [2] 83 38 [2] bc 24 }

  condition:
    any of them
}