rule TTP_XOR_WriteProcessMemory_7b90 {
  strings:
    $key_7b90 = { 2c e2 [2] 1e c0 [2] 18 f5 [2] 36 f5 [2] 09 e9 }

  condition:
    any of them
}