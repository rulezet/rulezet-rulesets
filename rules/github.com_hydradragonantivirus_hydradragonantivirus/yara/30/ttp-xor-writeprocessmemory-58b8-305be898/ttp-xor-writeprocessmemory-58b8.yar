rule TTP_XOR_WriteProcessMemory_58b8 {
  strings:
    $key_58b8 = { 0f ca [2] 3d e8 [2] 3b dd [2] 15 dd [2] 2a c1 }

  condition:
    any of them
}