rule TTP_XOR_WriteProcessMemory_77b8 {
  strings:
    $key_77b8 = { 20 ca [2] 12 e8 [2] 14 dd [2] 3a dd [2] 05 c1 }

  condition:
    any of them
}