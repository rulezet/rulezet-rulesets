rule TTP_XOR_WriteProcessMemory_5e8d {
  strings:
    $key_5e8d = { 09 ff [2] 3b dd [2] 3d e8 [2] 13 e8 [2] 2c f4 }

  condition:
    any of them
}