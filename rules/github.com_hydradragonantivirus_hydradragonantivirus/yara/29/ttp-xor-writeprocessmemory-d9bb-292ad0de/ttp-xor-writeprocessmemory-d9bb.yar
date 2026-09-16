rule TTP_XOR_WriteProcessMemory_d9bb {
  strings:
    $key_d9bb = { 8e c9 [2] bc eb [2] ba de [2] 94 de [2] ab c2 }

  condition:
    any of them
}