rule TTP_XOR_WriteProcessMemory_c6b8 {
  strings:
    $key_c6b8 = { 91 ca [2] a3 e8 [2] a5 dd [2] 8b dd [2] b4 c1 }

  condition:
    any of them
}