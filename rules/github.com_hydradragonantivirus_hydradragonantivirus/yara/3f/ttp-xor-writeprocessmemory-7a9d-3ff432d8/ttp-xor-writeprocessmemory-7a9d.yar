rule TTP_XOR_WriteProcessMemory_7a9d {
  strings:
    $key_7a9d = { 2d ef [2] 1f cd [2] 19 f8 [2] 37 f8 [2] 08 e4 }

  condition:
    any of them
}