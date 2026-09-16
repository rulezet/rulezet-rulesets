rule TTP_XOR_WriteProcessMemory_d9ff {
  strings:
    $key_d9ff = { 8e 8d [2] bc af [2] ba 9a [2] 94 9a [2] ab 86 }

  condition:
    any of them
}