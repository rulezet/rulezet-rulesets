rule TTP_XOR_WriteProcessMemory_01b8 {
  strings:
    $key_01b8 = { 56 ca [2] 64 e8 [2] 62 dd [2] 4c dd [2] 73 c1 }

  condition:
    any of them
}