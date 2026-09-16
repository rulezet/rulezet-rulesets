rule TTP_XOR_WriteProcessMemory_d6b8 {
  strings:
    $key_d6b8 = { 81 ca [2] b3 e8 [2] b5 dd [2] 9b dd [2] a4 c1 }

  condition:
    any of them
}