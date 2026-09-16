rule TTP_XOR_WriteProcessMemory_c9b8 {
  strings:
    $key_c9b8 = { 9e ca [2] ac e8 [2] aa dd [2] 84 dd [2] bb c1 }

  condition:
    any of them
}