rule TTP_XOR_WriteProcessMemory_e790 {
  strings:
    $key_e790 = { b0 e2 [2] 82 c0 [2] 84 f5 [2] aa f5 [2] 95 e9 }

  condition:
    any of them
}