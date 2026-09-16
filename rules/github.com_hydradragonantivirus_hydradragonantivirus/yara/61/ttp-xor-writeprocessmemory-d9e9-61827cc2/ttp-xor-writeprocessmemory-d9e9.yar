rule TTP_XOR_WriteProcessMemory_d9e9 {
  strings:
    $key_d9e9 = { 8e 9b [2] bc b9 [2] ba 8c [2] 94 8c [2] ab 90 }

  condition:
    any of them
}