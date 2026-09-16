rule TTP_XOR_WriteProcessMemory_ceea {
  strings:
    $key_ceea = { 99 98 [2] ab ba [2] ad 8f [2] 83 8f [2] bc 93 }

  condition:
    any of them
}