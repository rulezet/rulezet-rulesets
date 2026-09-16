rule TTP_XOR_WriteProcessMemory_ce6f {
  strings:
    $key_ce6f = { 99 1d [2] ab 3f [2] ad 0a [2] 83 0a [2] bc 16 }

  condition:
    any of them
}