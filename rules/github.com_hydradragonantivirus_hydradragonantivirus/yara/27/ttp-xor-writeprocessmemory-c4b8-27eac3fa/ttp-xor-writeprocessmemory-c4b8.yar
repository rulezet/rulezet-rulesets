rule TTP_XOR_WriteProcessMemory_c4b8 {
  strings:
    $key_c4b8 = { 93 ca [2] a1 e8 [2] a7 dd [2] 89 dd [2] b6 c1 }

  condition:
    any of them
}