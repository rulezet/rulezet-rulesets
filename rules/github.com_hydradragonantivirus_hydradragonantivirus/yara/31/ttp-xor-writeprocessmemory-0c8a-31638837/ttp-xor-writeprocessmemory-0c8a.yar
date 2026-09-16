rule TTP_XOR_WriteProcessMemory_0c8a {
  strings:
    $key_0c8a = { 5b f8 [2] 69 da [2] 6f ef [2] 41 ef [2] 7e f3 }

  condition:
    any of them
}