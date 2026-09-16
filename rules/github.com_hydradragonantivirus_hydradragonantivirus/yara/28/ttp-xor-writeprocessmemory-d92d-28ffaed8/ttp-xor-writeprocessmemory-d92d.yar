rule TTP_XOR_WriteProcessMemory_d92d {
  strings:
    $key_d92d = { 8e 5f [2] bc 7d [2] ba 48 [2] 94 48 [2] ab 54 }

  condition:
    any of them
}