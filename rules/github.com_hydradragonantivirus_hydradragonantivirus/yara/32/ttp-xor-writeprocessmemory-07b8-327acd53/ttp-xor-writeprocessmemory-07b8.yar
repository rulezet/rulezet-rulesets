rule TTP_XOR_WriteProcessMemory_07b8 {
  strings:
    $key_07b8 = { 50 ca [2] 62 e8 [2] 64 dd [2] 4a dd [2] 75 c1 }

  condition:
    any of them
}