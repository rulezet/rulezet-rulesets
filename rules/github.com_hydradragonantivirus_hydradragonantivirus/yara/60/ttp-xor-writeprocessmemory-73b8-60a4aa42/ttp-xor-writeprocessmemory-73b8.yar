rule TTP_XOR_WriteProcessMemory_73b8 {
  strings:
    $key_73b8 = { 24 ca [2] 16 e8 [2] 10 dd [2] 3e dd [2] 01 c1 }

  condition:
    any of them
}