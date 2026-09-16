rule TTP_XOR_WriteProcessMemory_71b8 {
  strings:
    $key_71b8 = { 26 ca [2] 14 e8 [2] 12 dd [2] 3c dd [2] 03 c1 }

  condition:
    any of them
}