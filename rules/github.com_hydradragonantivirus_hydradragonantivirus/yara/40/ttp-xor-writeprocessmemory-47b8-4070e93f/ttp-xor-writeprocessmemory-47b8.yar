rule TTP_XOR_WriteProcessMemory_47b8 {
  strings:
    $key_47b8 = { 10 ca [2] 22 e8 [2] 24 dd [2] 0a dd [2] 35 c1 }

  condition:
    any of them
}