rule TTP_XOR_WriteProcessMemory_7f85 {
  strings:
    $key_7f85 = { 28 f7 [2] 1a d5 [2] 1c e0 [2] 32 e0 [2] 0d fc }

  condition:
    any of them
}