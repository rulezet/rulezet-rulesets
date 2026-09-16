rule TTP_XOR_WriteProcessMemory_2d8a {
  strings:
    $key_2d8a = { 7a f8 [2] 48 da [2] 4e ef [2] 60 ef [2] 5f f3 }

  condition:
    any of them
}