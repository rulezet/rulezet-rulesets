rule TTP_XOR_WriteProcessMemory_278a {
  strings:
    $key_278a = { 70 f8 [2] 42 da [2] 44 ef [2] 6a ef [2] 55 f3 }

  condition:
    any of them
}