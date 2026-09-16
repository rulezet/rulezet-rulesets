rule TTP_XOR_WriteProcessMemory_ce08 {
  strings:
    $key_ce08 = { 99 7a [2] ab 58 [2] ad 6d [2] 83 6d [2] bc 71 }

  condition:
    any of them
}