rule TTP_XOR_WriteProcessMemory_7a8a {
  strings:
    $key_7a8a = { 2d f8 [2] 1f da [2] 19 ef [2] 37 ef [2] 08 f3 }

  condition:
    any of them
}