rule TTP_XOR_WriteProcessMemory_d9e6 {
  strings:
    $key_d9e6 = { 8e 94 [2] bc b6 [2] ba 83 [2] 94 83 [2] ab 9f }

  condition:
    any of them
}