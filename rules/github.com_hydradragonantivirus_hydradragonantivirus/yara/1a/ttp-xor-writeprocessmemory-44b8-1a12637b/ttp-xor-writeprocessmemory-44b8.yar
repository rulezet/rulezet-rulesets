rule TTP_XOR_WriteProcessMemory_44b8 {
  strings:
    $key_44b8 = { 13 ca [2] 21 e8 [2] 27 dd [2] 09 dd [2] 36 c1 }

  condition:
    any of them
}