rule TTP_XOR_WriteProcessMemory_e0e7 {
  strings:
    $key_e0e7 = { b7 95 [2] 85 b7 [2] 83 82 [2] ad 82 [2] 92 9e }

  condition:
    any of them
}