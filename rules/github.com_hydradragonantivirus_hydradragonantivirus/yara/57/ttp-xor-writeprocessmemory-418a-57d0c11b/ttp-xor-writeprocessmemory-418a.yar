rule TTP_XOR_WriteProcessMemory_418a {
  strings:
    $key_418a = { 16 f8 [2] 24 da [2] 22 ef [2] 0c ef [2] 33 f3 }

  condition:
    any of them
}