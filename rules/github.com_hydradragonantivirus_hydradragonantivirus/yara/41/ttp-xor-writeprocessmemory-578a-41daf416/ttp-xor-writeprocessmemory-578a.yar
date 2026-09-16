rule TTP_XOR_WriteProcessMemory_578a {
  strings:
    $key_578a = { 00 f8 [2] 32 da [2] 34 ef [2] 1a ef [2] 25 f3 }

  condition:
    any of them
}