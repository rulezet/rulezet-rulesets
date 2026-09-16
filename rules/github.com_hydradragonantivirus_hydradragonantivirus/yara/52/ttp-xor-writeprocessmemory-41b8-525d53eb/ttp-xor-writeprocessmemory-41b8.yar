rule TTP_XOR_WriteProcessMemory_41b8 {
  strings:
    $key_41b8 = { 16 ca [2] 24 e8 [2] 22 dd [2] 0c dd [2] 33 c1 }

  condition:
    any of them
}