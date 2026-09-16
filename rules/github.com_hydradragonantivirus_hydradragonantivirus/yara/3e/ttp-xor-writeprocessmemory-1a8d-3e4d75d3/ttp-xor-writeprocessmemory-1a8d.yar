rule TTP_XOR_WriteProcessMemory_1a8d {
  strings:
    $key_1a8d = { 4d ff [2] 7f dd [2] 79 e8 [2] 57 e8 [2] 68 f4 }

  condition:
    any of them
}