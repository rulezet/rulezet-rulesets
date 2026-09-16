rule TTP_XOR_WriteProcessMemory_2a8a {
  strings:
    $key_2a8a = { 7d f8 [2] 4f da [2] 49 ef [2] 67 ef [2] 58 f3 }

  condition:
    any of them
}