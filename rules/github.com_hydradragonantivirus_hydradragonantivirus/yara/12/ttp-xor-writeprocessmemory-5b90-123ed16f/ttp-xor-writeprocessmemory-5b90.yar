rule TTP_XOR_WriteProcessMemory_5b90 {
  strings:
    $key_5b90 = { 0c e2 [2] 3e c0 [2] 38 f5 [2] 16 f5 [2] 29 e9 }

  condition:
    any of them
}