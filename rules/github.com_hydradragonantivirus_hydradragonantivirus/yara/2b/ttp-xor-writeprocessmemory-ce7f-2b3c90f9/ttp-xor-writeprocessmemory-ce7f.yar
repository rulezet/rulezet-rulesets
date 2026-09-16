rule TTP_XOR_WriteProcessMemory_ce7f {
  strings:
    $key_ce7f = { 99 0d [2] ab 2f [2] ad 1a [2] 83 1a [2] bc 06 }

  condition:
    any of them
}