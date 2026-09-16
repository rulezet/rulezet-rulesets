rule TTP_XOR_WriteProcessMemory_7790 {
  strings:
    $key_7790 = { 20 e2 [2] 12 c0 [2] 14 f5 [2] 3a f5 [2] 05 e9 }

  condition:
    any of them
}