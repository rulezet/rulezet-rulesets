rule TTP_XOR_WriteProcessMemory_1e81 {
  strings:
    $key_1e81 = { 49 f3 [2] 7b d1 [2] 7d e4 [2] 53 e4 [2] 6c f8 }

  condition:
    any of them
}