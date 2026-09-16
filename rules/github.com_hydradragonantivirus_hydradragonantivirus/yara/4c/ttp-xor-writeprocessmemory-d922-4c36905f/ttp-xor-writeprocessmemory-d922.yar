rule TTP_XOR_WriteProcessMemory_d922 {
  strings:
    $key_d922 = { 8e 50 [2] bc 72 [2] ba 47 [2] 94 47 [2] ab 5b }

  condition:
    any of them
}