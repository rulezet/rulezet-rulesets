rule TTP_XOR_WriteProcessMemory_c3b8 {
  strings:
    $key_c3b8 = { 94 ca [2] a6 e8 [2] a0 dd [2] 8e dd [2] b1 c1 }

  condition:
    any of them
}