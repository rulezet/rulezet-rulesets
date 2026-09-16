rule TTP_XOR_WriteProcessMemory_d921 {
  strings:
    $key_d921 = { 8e 53 [2] bc 71 [2] ba 44 [2] 94 44 [2] ab 58 }

  condition:
    any of them
}