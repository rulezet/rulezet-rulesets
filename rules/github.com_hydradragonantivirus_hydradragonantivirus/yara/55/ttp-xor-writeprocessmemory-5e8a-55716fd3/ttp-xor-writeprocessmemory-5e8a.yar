rule TTP_XOR_WriteProcessMemory_5e8a {
  strings:
    $key_5e8a = { 09 f8 [2] 3b da [2] 3d ef [2] 13 ef [2] 2c f3 }

  condition:
    any of them
}