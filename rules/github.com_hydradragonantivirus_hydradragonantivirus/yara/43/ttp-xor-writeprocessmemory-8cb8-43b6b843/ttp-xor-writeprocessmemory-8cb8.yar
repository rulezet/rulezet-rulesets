rule TTP_XOR_WriteProcessMemory_8cb8 {
  strings:
    $key_8cb8 = { db ca [2] e9 e8 [2] ef dd [2] c1 dd [2] fe c1 }

  condition:
    any of them
}