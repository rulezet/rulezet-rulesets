rule TTP_XOR_WriteProcessMemory_e0b8 {
  strings:
    $key_e0b8 = { b7 ca [2] 85 e8 [2] 83 dd [2] ad dd [2] 92 c1 }

  condition:
    any of them
}