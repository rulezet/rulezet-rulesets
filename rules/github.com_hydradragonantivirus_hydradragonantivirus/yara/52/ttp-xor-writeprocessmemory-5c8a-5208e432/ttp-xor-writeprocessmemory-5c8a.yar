rule TTP_XOR_WriteProcessMemory_5c8a {
  strings:
    $key_5c8a = { 0b f8 [2] 39 da [2] 3f ef [2] 11 ef [2] 2e f3 }

  condition:
    any of them
}