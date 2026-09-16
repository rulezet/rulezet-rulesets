rule TTP_XOR_WriteProcessMemory_e1b8 {
  strings:
    $key_e1b8 = { b6 ca [2] 84 e8 [2] 82 dd [2] ac dd [2] 93 c1 }

  condition:
    any of them
}