rule TTP_XOR_WriteProcessMemory_4a9d {
  strings:
    $key_4a9d = { 1d ef [2] 2f cd [2] 29 f8 [2] 07 f8 [2] 38 e4 }

  condition:
    any of them
}