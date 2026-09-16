rule TTP_XOR_WriteProcessMemory_d91a {
  strings:
    $key_d91a = { 8e 68 [2] bc 4a [2] ba 7f [2] 94 7f [2] ab 63 }

  condition:
    any of them
}