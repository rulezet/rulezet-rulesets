rule TTP_XOR_WriteProcessMemory_d9a5 {
  strings:
    $key_d9a5 = { 8e d7 [2] bc f5 [2] ba c0 [2] 94 c0 [2] ab dc }

  condition:
    any of them
}