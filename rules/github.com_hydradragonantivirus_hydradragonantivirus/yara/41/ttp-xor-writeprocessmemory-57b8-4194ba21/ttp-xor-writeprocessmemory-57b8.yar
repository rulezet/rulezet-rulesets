rule TTP_XOR_WriteProcessMemory_57b8 {
  strings:
    $key_57b8 = { 00 ca [2] 32 e8 [2] 34 dd [2] 1a dd [2] 25 c1 }

  condition:
    any of them
}