rule TTP_XOR_WriteProcessMemory_f2b8 {
  strings:
    $key_f2b8 = { a5 ca [2] 97 e8 [2] 91 dd [2] bf dd [2] 80 c1 }

  condition:
    any of them
}