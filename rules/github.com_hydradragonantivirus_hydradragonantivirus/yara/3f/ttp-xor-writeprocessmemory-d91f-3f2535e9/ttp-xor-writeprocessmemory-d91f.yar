rule TTP_XOR_WriteProcessMemory_d91f {
  strings:
    $key_d91f = { 8e 6d [2] bc 4f [2] ba 7a [2] 94 7a [2] ab 66 }

  condition:
    any of them
}