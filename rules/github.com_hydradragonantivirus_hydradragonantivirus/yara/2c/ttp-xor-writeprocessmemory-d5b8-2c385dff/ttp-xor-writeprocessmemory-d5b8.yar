rule TTP_XOR_WriteProcessMemory_d5b8 {
  strings:
    $key_d5b8 = { 82 ca [2] b0 e8 [2] b6 dd [2] 98 dd [2] a7 c1 }

  condition:
    any of them
}