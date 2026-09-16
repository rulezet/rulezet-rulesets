rule TTP_XOR_WriteProcessMemory_0790 {
  strings:
    $key_0790 = { 50 e2 [2] 62 c0 [2] 64 f5 [2] 4a f5 [2] 75 e9 }

  condition:
    any of them
}