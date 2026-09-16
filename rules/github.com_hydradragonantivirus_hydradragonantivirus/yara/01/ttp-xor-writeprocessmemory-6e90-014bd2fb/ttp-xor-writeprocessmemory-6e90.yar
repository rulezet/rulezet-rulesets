rule TTP_XOR_WriteProcessMemory_6e90 {
  strings:
    $key_6e90 = { 39 e2 [2] 0b c0 [2] 0d f5 [2] 23 f5 [2] 1c e9 }

  condition:
    any of them
}