rule TTP_XOR_WriteProcessMemory_d9e3 {
  strings:
    $key_d9e3 = { 8e 91 [2] bc b3 [2] ba 86 [2] 94 86 [2] ab 9a }

  condition:
    any of them
}