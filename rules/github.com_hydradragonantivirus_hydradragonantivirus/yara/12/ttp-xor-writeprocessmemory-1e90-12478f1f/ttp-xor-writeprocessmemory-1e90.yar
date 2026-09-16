rule TTP_XOR_WriteProcessMemory_1e90 {
  strings:
    $key_1e90 = { 49 e2 [2] 7b c0 [2] 7d f5 [2] 53 f5 [2] 6c e9 }

  condition:
    any of them
}