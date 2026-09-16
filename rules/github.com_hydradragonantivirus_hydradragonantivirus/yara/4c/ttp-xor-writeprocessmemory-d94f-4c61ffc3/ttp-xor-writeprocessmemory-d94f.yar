rule TTP_XOR_WriteProcessMemory_d94f {
  strings:
    $key_d94f = { 8e 3d [2] bc 1f [2] ba 2a [2] 94 2a [2] ab 36 }

  condition:
    any of them
}