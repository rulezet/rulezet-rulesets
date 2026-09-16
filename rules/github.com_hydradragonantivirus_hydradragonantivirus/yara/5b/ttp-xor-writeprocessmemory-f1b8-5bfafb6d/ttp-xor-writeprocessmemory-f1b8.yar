rule TTP_XOR_WriteProcessMemory_f1b8 {
  strings:
    $key_f1b8 = { a6 ca [2] 94 e8 [2] 92 dd [2] bc dd [2] 83 c1 }

  condition:
    any of them
}