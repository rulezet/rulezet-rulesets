rule TTP_XOR_WriteProcessMemory_d91d {
  strings:
    $key_d91d = { 8e 6f [2] bc 4d [2] ba 78 [2] 94 78 [2] ab 64 }

  condition:
    any of them
}