rule TTP_XOR_WriteProcessMemory_0f85 {
  strings:
    $key_0f85 = { 58 f7 [2] 6a d5 [2] 6c e0 [2] 42 e0 [2] 7d fc }

  condition:
    any of them
}