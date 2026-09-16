rule TTP_XOR_WriteProcessMemory_1b8a {
  strings:
    $key_1b8a = { 4c f8 [2] 7e da [2] 78 ef [2] 56 ef [2] 69 f3 }

  condition:
    any of them
}