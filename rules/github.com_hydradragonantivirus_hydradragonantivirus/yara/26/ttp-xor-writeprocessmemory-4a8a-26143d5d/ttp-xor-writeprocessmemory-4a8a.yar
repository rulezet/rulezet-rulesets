rule TTP_XOR_WriteProcessMemory_4a8a {
  strings:
    $key_4a8a = { 1d f8 [2] 2f da [2] 29 ef [2] 07 ef [2] 38 f3 }

  condition:
    any of them
}