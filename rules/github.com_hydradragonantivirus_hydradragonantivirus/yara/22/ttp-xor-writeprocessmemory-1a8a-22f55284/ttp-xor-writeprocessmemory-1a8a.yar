rule TTP_XOR_WriteProcessMemory_1a8a {
  strings:
    $key_1a8a = { 4d f8 [2] 7f da [2] 79 ef [2] 57 ef [2] 68 f3 }

  condition:
    any of them
}