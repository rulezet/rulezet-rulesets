rule TTP_XOR_WriteProcessMemory_53b8 {
  strings:
    $key_53b8 = { 04 ca [2] 36 e8 [2] 30 dd [2] 1e dd [2] 21 c1 }

  condition:
    any of them
}