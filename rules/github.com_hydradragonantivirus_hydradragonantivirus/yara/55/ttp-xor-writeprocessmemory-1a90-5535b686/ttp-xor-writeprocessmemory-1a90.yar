rule TTP_XOR_WriteProcessMemory_1a90 {
  strings:
    $key_1a90 = { 4d e2 [2] 7f c0 [2] 79 f5 [2] 57 f5 [2] 68 e9 }

  condition:
    any of them
}