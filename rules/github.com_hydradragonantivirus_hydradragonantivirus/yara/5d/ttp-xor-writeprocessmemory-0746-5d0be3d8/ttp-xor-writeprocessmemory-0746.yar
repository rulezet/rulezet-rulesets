rule TTP_XOR_WriteProcessMemory_0746 {
  strings:
    $key_0746 = { 50 34 [2] 62 16 [2] 64 23 [2] 4a 23 [2] 75 3f }

  condition:
    any of them
}