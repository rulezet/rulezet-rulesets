rule TTP_XOR_WriteProcessMemory_d3b8 {
  strings:
    $key_d3b8 = { 84 ca [2] b6 e8 [2] b0 dd [2] 9e dd [2] a1 c1 }

  condition:
    any of them
}