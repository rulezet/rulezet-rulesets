rule TTP_XOR_WriteProcessMemory_5790 {
  strings:
    $key_5790 = { 00 e2 [2] 32 c0 [2] 34 f5 [2] 1a f5 [2] 25 e9 }

  condition:
    any of them
}