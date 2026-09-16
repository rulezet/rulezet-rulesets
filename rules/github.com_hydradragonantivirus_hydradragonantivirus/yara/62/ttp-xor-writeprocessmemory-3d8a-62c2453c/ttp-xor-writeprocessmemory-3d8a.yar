rule TTP_XOR_WriteProcessMemory_3d8a {
  strings:
    $key_3d8a = { 6a f8 [2] 58 da [2] 5e ef [2] 70 ef [2] 4f f3 }

  condition:
    any of them
}