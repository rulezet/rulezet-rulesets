rule TTP_XOR_WriteProcessMemory_6b8d {
  strings:
    $key_6b8d = { 3c ff [2] 0e dd [2] 08 e8 [2] 26 e8 [2] 19 f4 }

  condition:
    any of them
}