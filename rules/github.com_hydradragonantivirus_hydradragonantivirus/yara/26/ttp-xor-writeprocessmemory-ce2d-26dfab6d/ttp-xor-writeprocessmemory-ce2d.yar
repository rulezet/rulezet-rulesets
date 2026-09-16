rule TTP_XOR_WriteProcessMemory_ce2d {
  strings:
    $key_ce2d = { 99 5f [2] ab 7d [2] ad 48 [2] 83 48 [2] bc 54 }

  condition:
    any of them
}