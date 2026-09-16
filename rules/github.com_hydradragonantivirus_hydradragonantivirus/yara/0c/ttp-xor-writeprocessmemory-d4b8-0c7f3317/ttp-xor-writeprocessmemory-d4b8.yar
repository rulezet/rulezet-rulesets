rule TTP_XOR_WriteProcessMemory_d4b8 {
  strings:
    $key_d4b8 = { 83 ca [2] b1 e8 [2] b7 dd [2] 99 dd [2] a6 c1 }

  condition:
    any of them
}