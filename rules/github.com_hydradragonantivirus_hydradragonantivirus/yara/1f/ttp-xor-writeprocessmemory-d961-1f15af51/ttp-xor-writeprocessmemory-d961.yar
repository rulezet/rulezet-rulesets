rule TTP_XOR_WriteProcessMemory_d961 {
  strings:
    $key_d961 = { 8e 13 [2] bc 31 [2] ba 04 [2] 94 04 [2] ab 18 }

  condition:
    any of them
}