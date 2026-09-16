rule TTP_XOR_WriteProcessMemory_5090 {
  strings:
    $key_5090 = { 07 e2 [2] 35 c0 [2] 33 f5 [2] 1d f5 [2] 22 e9 }

  condition:
    any of them
}