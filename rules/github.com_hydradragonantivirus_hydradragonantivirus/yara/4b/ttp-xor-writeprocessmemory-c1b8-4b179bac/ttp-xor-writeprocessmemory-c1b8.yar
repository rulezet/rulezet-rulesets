rule TTP_XOR_WriteProcessMemory_c1b8 {
  strings:
    $key_c1b8 = { 96 ca [2] a4 e8 [2] a2 dd [2] 8c dd [2] b3 c1 }

  condition:
    any of them
}