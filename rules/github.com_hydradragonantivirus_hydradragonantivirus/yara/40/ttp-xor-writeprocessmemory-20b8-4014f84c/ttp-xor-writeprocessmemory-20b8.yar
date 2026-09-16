rule TTP_XOR_WriteProcessMemory_20b8 {
  strings:
    $key_20b8 = { 77 ca [2] 45 e8 [2] 43 dd [2] 6d dd [2] 52 c1 }

  condition:
    any of them
}