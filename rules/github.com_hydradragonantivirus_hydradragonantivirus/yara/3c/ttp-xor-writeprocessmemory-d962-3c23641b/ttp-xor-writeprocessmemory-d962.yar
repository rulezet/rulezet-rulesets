rule TTP_XOR_WriteProcessMemory_d962 {
  strings:
    $key_d962 = { 8e 10 [2] bc 32 [2] ba 07 [2] 94 07 [2] ab 1b }

  condition:
    any of them
}