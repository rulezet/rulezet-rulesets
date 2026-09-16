rule TTP_XOR_WriteProcessMemory_c0b8 {
  strings:
    $key_c0b8 = { 97 ca [2] a5 e8 [2] a3 dd [2] 8d dd [2] b2 c1 }

  condition:
    any of them
}