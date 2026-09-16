rule TTP_XOR_WriteProcessMemory_448a {
  strings:
    $key_448a = { 13 f8 [2] 21 da [2] 27 ef [2] 09 ef [2] 36 f3 }

  condition:
    any of them
}