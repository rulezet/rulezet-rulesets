rule TTP_XOR_WriteProcessMemory_d90a {
  strings:
    $key_d90a = { 8e 78 [2] bc 5a [2] ba 6f [2] 94 6f [2] ab 73 }

  condition:
    any of them
}