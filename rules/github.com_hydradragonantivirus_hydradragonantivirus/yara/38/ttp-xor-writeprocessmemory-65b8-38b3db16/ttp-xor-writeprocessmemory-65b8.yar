rule TTP_XOR_WriteProcessMemory_65b8 {
  strings:
    $key_65b8 = { 32 ca [2] 00 e8 [2] 06 dd [2] 28 dd [2] 17 c1 }

  condition:
    any of them
}