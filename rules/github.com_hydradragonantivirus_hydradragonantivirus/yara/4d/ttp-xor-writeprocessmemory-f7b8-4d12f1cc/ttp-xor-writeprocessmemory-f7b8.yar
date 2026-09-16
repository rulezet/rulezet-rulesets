rule TTP_XOR_WriteProcessMemory_f7b8 {
  strings:
    $key_f7b8 = { a0 ca [2] 92 e8 [2] 94 dd [2] ba dd [2] 85 c1 }

  condition:
    any of them
}