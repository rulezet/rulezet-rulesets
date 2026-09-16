rule TTP_XOR_WriteProcessMemory_d9fa {
  strings:
    $key_d9fa = { 8e 88 [2] bc aa [2] ba 9f [2] 94 9f [2] ab 83 }

  condition:
    any of them
}