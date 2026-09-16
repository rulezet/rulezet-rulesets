rule TTP_XOR_WriteProcessMemory_7c8a {
  strings:
    $key_7c8a = { 2b f8 [2] 19 da [2] 1f ef [2] 31 ef [2] 0e f3 }

  condition:
    any of them
}