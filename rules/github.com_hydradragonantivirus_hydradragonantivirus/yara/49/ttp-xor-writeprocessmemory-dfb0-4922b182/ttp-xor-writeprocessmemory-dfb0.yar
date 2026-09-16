rule TTP_XOR_WriteProcessMemory_dfb0 {
  strings:
    $key_dfb0 = { 88 c2 [2] ba e0 [2] bc d5 [2] 92 d5 [2] ad c9 }

  condition:
    any of them
}