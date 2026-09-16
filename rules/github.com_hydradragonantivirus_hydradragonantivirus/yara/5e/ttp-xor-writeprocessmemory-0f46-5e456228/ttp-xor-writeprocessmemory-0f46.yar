rule TTP_XOR_WriteProcessMemory_0f46 {
  strings:
    $key_0f46 = { 58 34 [2] 6a 16 [2] 6c 23 [2] 42 23 [2] 7d 3f }

  condition:
    any of them
}