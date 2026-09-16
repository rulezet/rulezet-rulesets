rule TTP_XOR_WriteProcessMemory_4d8d {
  strings:
    $key_4d8d = { 1a ff [2] 28 dd [2] 2e e8 [2] 00 e8 [2] 3f f4 }

  condition:
    any of them
}