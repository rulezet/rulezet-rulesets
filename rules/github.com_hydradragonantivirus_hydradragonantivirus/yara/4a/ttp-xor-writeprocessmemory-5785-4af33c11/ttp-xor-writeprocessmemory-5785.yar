rule TTP_XOR_WriteProcessMemory_5785 {
  strings:
    $key_5785 = { 00 f7 [2] 32 d5 [2] 34 e0 [2] 1a e0 [2] 25 fc }

  condition:
    any of them
}