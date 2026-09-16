rule TTP_XOR_WriteProcessMemory_cefa {
  strings:
    $key_cefa = { 99 88 [2] ab aa [2] ad 9f [2] 83 9f [2] bc 83 }

  condition:
    any of them
}