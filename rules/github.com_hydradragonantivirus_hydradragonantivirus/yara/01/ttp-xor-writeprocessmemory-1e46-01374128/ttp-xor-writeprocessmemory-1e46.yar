rule TTP_XOR_WriteProcessMemory_1e46 {
  strings:
    $key_1e46 = { 49 34 [2] 7b 16 [2] 7d 23 [2] 53 23 [2] 6c 3f }

  condition:
    any of them
}