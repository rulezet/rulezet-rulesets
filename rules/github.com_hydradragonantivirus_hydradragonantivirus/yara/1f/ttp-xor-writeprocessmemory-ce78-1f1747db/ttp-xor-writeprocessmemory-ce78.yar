rule TTP_XOR_WriteProcessMemory_ce78 {
  strings:
    $key_ce78 = { 99 0a [2] ab 28 [2] ad 1d [2] 83 1d [2] bc 01 }

  condition:
    any of them
}