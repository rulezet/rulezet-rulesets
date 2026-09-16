rule TTP_XOR_WriteProcessMemory_1e9d {
  strings:
    $key_1e9d = { 49 ef [2] 7b cd [2] 7d f8 [2] 53 f8 [2] 6c e4 }

  condition:
    any of them
}