rule TTP_XOR_WriteProcessMemory_17b8 {
  strings:
    $key_17b8 = { 40 ca [2] 72 e8 [2] 74 dd [2] 5a dd [2] 65 c1 }

  condition:
    any of them
}