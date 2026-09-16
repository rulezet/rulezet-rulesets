rule TTP_XOR_WriteProcessMemory_70b8 {
  strings:
    $key_70b8 = { 27 ca [2] 15 e8 [2] 13 dd [2] 3d dd [2] 02 c1 }

  condition:
    any of them
}