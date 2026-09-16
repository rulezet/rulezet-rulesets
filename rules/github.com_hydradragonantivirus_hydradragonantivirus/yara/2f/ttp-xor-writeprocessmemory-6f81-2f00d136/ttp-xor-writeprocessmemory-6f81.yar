rule TTP_XOR_WriteProcessMemory_6f81 {
  strings:
    $key_6f81 = { 38 f3 [2] 0a d1 [2] 0c e4 [2] 22 e4 [2] 1d f8 }

  condition:
    any of them
}