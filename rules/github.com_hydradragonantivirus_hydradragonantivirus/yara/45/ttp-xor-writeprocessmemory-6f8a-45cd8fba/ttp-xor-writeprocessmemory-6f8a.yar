rule TTP_XOR_WriteProcessMemory_6f8a {
  strings:
    $key_6f8a = { 38 f8 [2] 0a da [2] 0c ef [2] 22 ef [2] 1d f3 }

  condition:
    any of them
}