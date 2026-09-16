rule TTP_XOR_WriteProcessMemory_0e90 {
  strings:
    $key_0e90 = { 59 e2 [2] 6b c0 [2] 6d f5 [2] 43 f5 [2] 7c e9 }

  condition:
    any of them
}