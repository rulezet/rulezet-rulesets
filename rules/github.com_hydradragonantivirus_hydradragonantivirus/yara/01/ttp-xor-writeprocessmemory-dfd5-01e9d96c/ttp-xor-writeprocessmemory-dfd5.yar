rule TTP_XOR_WriteProcessMemory_dfd5 {
  strings:
    $key_dfd5 = { 88 a7 [2] ba 85 [2] bc b0 [2] 92 b0 [2] ad ac }

  condition:
    any of them
}