rule TTP_XOR_WriteProcessMemory_7bb1 {
  strings:
    $key_7bb1 = { 2c c3 [2] 1e e1 [2] 18 d4 [2] 36 d4 [2] 09 c8 }

  condition:
    any of them
}