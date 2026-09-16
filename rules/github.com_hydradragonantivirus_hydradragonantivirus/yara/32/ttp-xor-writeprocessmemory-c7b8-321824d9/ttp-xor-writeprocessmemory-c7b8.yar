rule TTP_XOR_WriteProcessMemory_c7b8 {
  strings:
    $key_c7b8 = { 90 ca [2] a2 e8 [2] a4 dd [2] 8a dd [2] b5 c1 }

  condition:
    any of them
}