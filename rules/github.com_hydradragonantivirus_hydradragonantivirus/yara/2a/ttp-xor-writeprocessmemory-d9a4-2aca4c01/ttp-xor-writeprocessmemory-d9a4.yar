rule TTP_XOR_WriteProcessMemory_d9a4 {
  strings:
    $key_d9a4 = { 8e d6 [2] bc f4 [2] ba c1 [2] 94 c1 [2] ab dd }

  condition:
    any of them
}