rule TTP_XOR_WriteProcessMemory_d929 {
  strings:
    $key_d929 = { 8e 5b [2] bc 79 [2] ba 4c [2] 94 4c [2] ab 50 }

  condition:
    any of them
}