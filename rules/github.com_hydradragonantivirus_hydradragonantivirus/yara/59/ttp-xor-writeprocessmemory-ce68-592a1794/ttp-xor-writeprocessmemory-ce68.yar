rule TTP_XOR_WriteProcessMemory_ce68 {
  strings:
    $key_ce68 = { 99 1a [2] ab 38 [2] ad 0d [2] 83 0d [2] bc 11 }

  condition:
    any of them
}