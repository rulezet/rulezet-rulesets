rule TTP_XOR_WriteProcessMemory_4b8d {
  strings:
    $key_4b8d = { 1c ff [2] 2e dd [2] 28 e8 [2] 06 e8 [2] 39 f4 }

  condition:
    any of them
}