rule TTP_XOR_WriteProcessMemory_dfb4 {
  strings:
    $key_dfb4 = { 88 c6 [2] ba e4 [2] bc d1 [2] 92 d1 [2] ad cd }

  condition:
    any of them
}