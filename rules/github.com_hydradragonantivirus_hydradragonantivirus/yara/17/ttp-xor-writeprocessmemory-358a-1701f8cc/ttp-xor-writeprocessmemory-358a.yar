rule TTP_XOR_WriteProcessMemory_358a {
  strings:
    $key_358a = { 62 f8 [2] 50 da [2] 56 ef [2] 78 ef [2] 47 f3 }

  condition:
    any of them
}