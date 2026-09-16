rule TTP_XOR_WriteProcessMemory_3a8a {
  strings:
    $key_3a8a = { 6d f8 [2] 5f da [2] 59 ef [2] 77 ef [2] 48 f3 }

  condition:
    any of them
}