rule TTP_XOR_WriteProcessMemory_5d8a {
  strings:
    $key_5d8a = { 0a f8 [2] 38 da [2] 3e ef [2] 10 ef [2] 2f f3 }

  condition:
    any of them
}