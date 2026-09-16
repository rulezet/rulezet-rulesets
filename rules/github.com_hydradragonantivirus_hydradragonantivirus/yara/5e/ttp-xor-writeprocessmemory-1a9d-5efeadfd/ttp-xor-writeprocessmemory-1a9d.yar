rule TTP_XOR_WriteProcessMemory_1a9d {
  strings:
    $key_1a9d = { 4d ef [2] 7f cd [2] 79 f8 [2] 57 f8 [2] 68 e4 }

  condition:
    any of them
}