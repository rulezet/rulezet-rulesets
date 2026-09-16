rule TTP_XOR_WriteProcessMemory_e190 {
  strings:
    $key_e190 = { b6 e2 [2] 84 c0 [2] 82 f5 [2] ac f5 [2] 93 e9 }

  condition:
    any of them
}