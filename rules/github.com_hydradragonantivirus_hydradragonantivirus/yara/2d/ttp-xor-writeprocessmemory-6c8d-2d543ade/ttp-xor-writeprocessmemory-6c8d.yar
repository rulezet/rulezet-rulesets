rule TTP_XOR_WriteProcessMemory_6c8d {
  strings:
    $key_6c8d = { 3b ff [2] 09 dd [2] 0f e8 [2] 21 e8 [2] 1e f4 }

  condition:
    any of them
}