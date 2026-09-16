rule TTP_XOR_WriteProcessMemory_15b8 {
  strings:
    $key_15b8 = { 42 ca [2] 70 e8 [2] 76 dd [2] 58 dd [2] 67 c1 }

  condition:
    any of them
}