rule TTP_XOR_WriteProcessMemory_4f9a {
  strings:
    $key_4f9a = { 18 e8 [2] 2a ca [2] 2c ff [2] 02 ff [2] 3d e3 }

  condition:
    any of them
}