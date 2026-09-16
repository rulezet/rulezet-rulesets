rule TTP_XOR_WriteProcessMemory_0e8a {
  strings:
    $key_0e8a = { 59 f8 [2] 6b da [2] 6d ef [2] 43 ef [2] 7c f3 }

  condition:
    any of them
}