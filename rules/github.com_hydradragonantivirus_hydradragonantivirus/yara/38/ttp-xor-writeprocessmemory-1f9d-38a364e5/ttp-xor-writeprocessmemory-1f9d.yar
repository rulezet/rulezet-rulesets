rule TTP_XOR_WriteProcessMemory_1f9d {
  strings:
    $key_1f9d = { 48 ef [2] 7a cd [2] 7c f8 [2] 52 f8 [2] 6d e4 }

  condition:
    any of them
}