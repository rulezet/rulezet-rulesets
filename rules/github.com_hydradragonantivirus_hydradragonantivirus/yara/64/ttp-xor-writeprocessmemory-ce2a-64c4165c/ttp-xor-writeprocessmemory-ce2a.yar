rule TTP_XOR_WriteProcessMemory_ce2a {
  strings:
    $key_ce2a = { 99 58 [2] ab 7a [2] ad 4f [2] 83 4f [2] bc 53 }

  condition:
    any of them
}