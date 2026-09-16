rule TTP_XOR_WriteProcessMemory_3f8a {
  strings:
    $key_3f8a = { 68 f8 [2] 5a da [2] 5c ef [2] 72 ef [2] 4d f3 }

  condition:
    any of them
}