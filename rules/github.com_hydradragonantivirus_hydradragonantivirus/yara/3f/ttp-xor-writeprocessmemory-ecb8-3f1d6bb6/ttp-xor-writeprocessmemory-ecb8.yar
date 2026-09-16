rule TTP_XOR_WriteProcessMemory_ecb8 {
  strings:
    $key_ecb8 = { bb ca [2] 89 e8 [2] 8f dd [2] a1 dd [2] 9e c1 }

  condition:
    any of them
}