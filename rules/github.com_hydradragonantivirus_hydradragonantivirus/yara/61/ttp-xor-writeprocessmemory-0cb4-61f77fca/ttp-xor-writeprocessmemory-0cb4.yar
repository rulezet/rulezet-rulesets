rule TTP_XOR_WriteProcessMemory_0cb4 {
  strings:
    $key_0cb4 = { 5b c6 [2] 69 e4 [2] 6f d1 [2] 41 d1 [2] 7e cd }

  condition:
    any of them
}