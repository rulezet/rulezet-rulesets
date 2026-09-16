rule TTP_XOR_WriteProcessMemory_57f8 {
  strings:
    $key_57f8 = { 00 8a [2] 32 a8 [2] 34 9d [2] 1a 9d [2] 25 81 }

  condition:
    any of them
}