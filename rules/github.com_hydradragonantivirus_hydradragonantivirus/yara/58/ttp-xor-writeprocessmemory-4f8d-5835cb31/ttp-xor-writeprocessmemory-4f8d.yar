rule TTP_XOR_WriteProcessMemory_4f8d {
  strings:
    $key_4f8d = { 18 ff [2] 2a dd [2] 2c e8 [2] 02 e8 [2] 3d f4 }

  condition:
    any of them
}