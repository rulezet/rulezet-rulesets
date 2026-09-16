rule TTP_XOR_WriteProcessMemory_d957 {
  strings:
    $key_d957 = { 8e 25 [2] bc 07 [2] ba 32 [2] 94 32 [2] ab 2e }

  condition:
    any of them
}