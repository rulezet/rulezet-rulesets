rule TTP_XOR_WriteProcessMemory_40b8 {
  strings:
    $key_40b8 = { 17 ca [2] 25 e8 [2] 23 dd [2] 0d dd [2] 32 c1 }

  condition:
    any of them
}