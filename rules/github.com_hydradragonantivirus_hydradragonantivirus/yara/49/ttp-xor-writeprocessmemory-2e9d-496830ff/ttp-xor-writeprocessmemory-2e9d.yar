rule TTP_XOR_WriteProcessMemory_2e9d {
  strings:
    $key_2e9d = { 79 ef [2] 4b cd [2] 4d f8 [2] 63 f8 [2] 5c e4 }

  condition:
    any of them
}