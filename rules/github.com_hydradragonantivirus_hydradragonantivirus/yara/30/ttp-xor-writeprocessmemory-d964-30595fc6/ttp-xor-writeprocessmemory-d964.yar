rule TTP_XOR_WriteProcessMemory_d964 {
  strings:
    $key_d964 = { 8e 16 [2] bc 34 [2] ba 01 [2] 94 01 [2] ab 1d }

  condition:
    any of them
}