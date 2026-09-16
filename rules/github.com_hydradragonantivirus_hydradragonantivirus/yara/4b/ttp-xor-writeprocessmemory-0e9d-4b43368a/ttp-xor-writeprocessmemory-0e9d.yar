rule TTP_XOR_WriteProcessMemory_0e9d {
  strings:
    $key_0e9d = { 59 ef [2] 6b cd [2] 6d f8 [2] 43 f8 [2] 7c e4 }

  condition:
    any of them
}