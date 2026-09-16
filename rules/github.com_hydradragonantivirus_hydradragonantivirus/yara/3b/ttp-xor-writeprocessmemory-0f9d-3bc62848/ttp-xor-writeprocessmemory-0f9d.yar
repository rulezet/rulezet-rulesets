rule TTP_XOR_WriteProcessMemory_0f9d {
  strings:
    $key_0f9d = { 58 ef [2] 6a cd [2] 6c f8 [2] 42 f8 [2] 7d e4 }

  condition:
    any of them
}