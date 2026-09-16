rule TTP_XOR_WriteProcessMemory_e7f6 {
  strings:
    $key_e7f6 = { b0 84 [2] 82 a6 [2] 84 93 [2] aa 93 [2] 95 8f }

  condition:
    any of them
}