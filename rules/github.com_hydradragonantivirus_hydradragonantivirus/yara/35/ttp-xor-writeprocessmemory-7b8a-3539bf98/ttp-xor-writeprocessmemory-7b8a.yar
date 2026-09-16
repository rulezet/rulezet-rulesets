rule TTP_XOR_WriteProcessMemory_7b8a {
  strings:
    $key_7b8a = { 2c f8 [2] 1e da [2] 18 ef [2] 36 ef [2] 09 f3 }

  condition:
    any of them
}