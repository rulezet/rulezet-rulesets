rule TTP_XOR_WriteProcessMemory_50b8 {
  strings:
    $key_50b8 = { 07 ca [2] 35 e8 [2] 33 dd [2] 1d dd [2] 22 c1 }

  condition:
    any of them
}