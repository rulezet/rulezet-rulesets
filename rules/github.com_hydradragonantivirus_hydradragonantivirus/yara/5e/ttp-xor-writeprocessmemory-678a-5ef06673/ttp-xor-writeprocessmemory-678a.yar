rule TTP_XOR_WriteProcessMemory_678a {
  strings:
    $key_678a = { 30 f8 [2] 02 da [2] 04 ef [2] 2a ef [2] 15 f3 }

  condition:
    any of them
}