rule TTP_XOR_WriteProcessMemory_5c8d {
  strings:
    $key_5c8d = { 0b ff [2] 39 dd [2] 3f e8 [2] 11 e8 [2] 2e f4 }

  condition:
    any of them
}