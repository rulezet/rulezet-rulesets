rule TTP_XOR_WriteProcessMemory_25b8 {
  strings:
    $key_25b8 = { 72 ca [2] 40 e8 [2] 46 dd [2] 68 dd [2] 57 c1 }

  condition:
    any of them
}