rule TTP_XOR_WriteProcessMemory_3b8d {
  strings:
    $key_3b8d = { 6c ff [2] 5e dd [2] 58 e8 [2] 76 e8 [2] 49 f4 }

  condition:
    any of them
}