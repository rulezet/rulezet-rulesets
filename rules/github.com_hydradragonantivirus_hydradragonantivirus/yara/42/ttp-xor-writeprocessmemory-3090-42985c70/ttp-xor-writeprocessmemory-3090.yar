rule TTP_XOR_WriteProcessMemory_3090 {
  strings:
    $key_3090 = { 67 e2 [2] 55 c0 [2] 53 f5 [2] 7d f5 [2] 42 e9 }

  condition:
    any of them
}