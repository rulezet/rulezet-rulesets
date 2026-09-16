rule TTP_XOR_WriteProcessMemory_e746 {
  strings:
    $key_e746 = { b0 34 [2] 82 16 [2] 84 23 [2] aa 23 [2] 95 3f }

  condition:
    any of them
}