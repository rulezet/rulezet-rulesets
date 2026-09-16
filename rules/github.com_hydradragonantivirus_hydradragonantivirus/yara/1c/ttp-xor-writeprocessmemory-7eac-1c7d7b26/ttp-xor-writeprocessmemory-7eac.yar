rule TTP_XOR_WriteProcessMemory_7eac {
  strings:
    $key_7eac = { 29 de [2] 1b fc [2] 1d c9 [2] 33 c9 [2] 0c d5 }

  condition:
    any of them
}