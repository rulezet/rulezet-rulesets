rule TTP_XOR_WriteProcessMemory_4090 {
  strings:
    $key_4090 = { 17 e2 [2] 25 c0 [2] 23 f5 [2] 0d f5 [2] 32 e9 }

  condition:
    any of them
}