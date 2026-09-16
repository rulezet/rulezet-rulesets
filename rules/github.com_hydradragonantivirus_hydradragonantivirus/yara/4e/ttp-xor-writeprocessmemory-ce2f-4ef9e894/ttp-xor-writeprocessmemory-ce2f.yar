rule TTP_XOR_WriteProcessMemory_ce2f {
  strings:
    $key_ce2f = { 99 5d [2] ab 7f [2] ad 4a [2] 83 4a [2] bc 56 }

  condition:
    any of them
}