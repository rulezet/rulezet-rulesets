rule TTP_XOR_WriteProcessMemory_dfb8 {
  strings:
    $key_dfb8 = { 88 ca [2] ba e8 [2] bc dd [2] 92 dd [2] ad c1 }

  condition:
    any of them
}