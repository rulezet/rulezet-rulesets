rule TTP_XOR_WriteProcessMemory_7346 {
  strings:
    $key_7346 = { 24 34 [2] 16 16 [2] 10 23 [2] 3e 23 [2] 01 3f }

  condition:
    any of them
}