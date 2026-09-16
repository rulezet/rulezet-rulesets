rule TTP_XOR_WriteProcessMemory_ea8a {
  strings:
    $key_ea8a = { bd f8 [2] 8f da [2] 89 ef [2] a7 ef [2] 98 f3 }

  condition:
    any of them
}