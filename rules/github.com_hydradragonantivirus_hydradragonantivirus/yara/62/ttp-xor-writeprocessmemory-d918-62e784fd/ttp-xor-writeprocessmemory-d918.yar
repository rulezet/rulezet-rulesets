rule TTP_XOR_WriteProcessMemory_d918 {
  strings:
    $key_d918 = { 8e 6a [2] bc 48 [2] ba 7d [2] 94 7d [2] ab 61 }

  condition:
    any of them
}