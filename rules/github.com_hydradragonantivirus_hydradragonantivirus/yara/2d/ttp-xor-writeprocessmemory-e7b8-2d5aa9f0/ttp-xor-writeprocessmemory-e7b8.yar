rule TTP_XOR_WriteProcessMemory_e7b8 {
  strings:
    $key_e7b8 = { b0 ca [2] 82 e8 [2] 84 dd [2] aa dd [2] 95 c1 }

  condition:
    any of them
}