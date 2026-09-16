rule TTP_XOR_WriteProcessMemory_d94d {
  strings:
    $key_d94d = { 8e 3f [2] bc 1d [2] ba 28 [2] 94 28 [2] ab 34 }

  condition:
    any of them
}