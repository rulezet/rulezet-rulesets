rule TTP_XOR_WriteProcessMemory_478a {
  strings:
    $key_478a = { 10 f8 [2] 22 da [2] 24 ef [2] 0a ef [2] 35 f3 }

  condition:
    any of them
}