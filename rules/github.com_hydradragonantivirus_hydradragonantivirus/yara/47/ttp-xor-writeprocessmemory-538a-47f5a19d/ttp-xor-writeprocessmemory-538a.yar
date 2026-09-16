rule TTP_XOR_WriteProcessMemory_538a {
  strings:
    $key_538a = { 04 f8 [2] 36 da [2] 30 ef [2] 1e ef [2] 21 f3 }

  condition:
    any of them
}