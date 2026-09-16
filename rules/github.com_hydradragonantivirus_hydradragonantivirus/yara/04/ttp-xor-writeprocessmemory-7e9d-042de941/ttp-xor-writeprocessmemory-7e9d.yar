rule TTP_XOR_WriteProcessMemory_7e9d {
  strings:
    $key_7e9d = { 29 ef [2] 1b cd [2] 1d f8 [2] 33 f8 [2] 0c e4 }

  condition:
    any of them
}