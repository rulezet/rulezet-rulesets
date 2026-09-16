rule TTP_XOR_WriteProcessMemory_ce1d {
  strings:
    $key_ce1d = { 99 6f [2] ab 4d [2] ad 78 [2] 83 78 [2] bc 64 }

  condition:
    any of them
}