rule TTP_XOR_WriteProcessMemory_0f8d {
  strings:
    $key_0f8d = { 58 ff [2] 6a dd [2] 6c e8 [2] 42 e8 [2] 7d f4 }

  condition:
    any of them
}