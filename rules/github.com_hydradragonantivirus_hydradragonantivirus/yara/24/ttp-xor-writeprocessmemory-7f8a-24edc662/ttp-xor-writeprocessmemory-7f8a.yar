rule TTP_XOR_WriteProcessMemory_7f8a {
  strings:
    $key_7f8a = { 28 f8 [2] 1a da [2] 1c ef [2] 32 ef [2] 0d f3 }

  condition:
    any of them
}