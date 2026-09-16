rule TTP_XOR_WriteProcessMemory_3f8d {
  strings:
    $key_3f8d = { 68 ff [2] 5a dd [2] 5c e8 [2] 72 e8 [2] 4d f4 }

  condition:
    any of them
}