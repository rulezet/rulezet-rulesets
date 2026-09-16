rule TTP_XOR_WriteProcessMemory_d923 {
  strings:
    $key_d923 = { 8e 51 [2] bc 73 [2] ba 46 [2] 94 46 [2] ab 5a }

  condition:
    any of them
}