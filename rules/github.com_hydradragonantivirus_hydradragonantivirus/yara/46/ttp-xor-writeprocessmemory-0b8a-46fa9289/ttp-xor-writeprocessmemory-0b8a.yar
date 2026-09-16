rule TTP_XOR_WriteProcessMemory_0b8a {
  strings:
    $key_0b8a = { 5c f8 [2] 6e da [2] 68 ef [2] 46 ef [2] 79 f3 }

  condition:
    any of them
}