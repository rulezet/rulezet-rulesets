rule TTP_XOR_WriteProcessMemory_d911 {
  strings:
    $key_d911 = { 8e 63 [2] bc 41 [2] ba 74 [2] 94 74 [2] ab 68 }

  condition:
    any of them
}