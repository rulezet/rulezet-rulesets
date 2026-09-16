rule TTP_XOR_WriteProcessMemory_7cb4 {
  strings:
    $key_7cb4 = { 2b c6 [2] 19 e4 [2] 1f d1 [2] 31 d1 [2] 0e cd }

  condition:
    any of them
}