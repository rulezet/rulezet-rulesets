rule TTP_XOR_WriteProcessMemory_1ee6 {
  strings:
    $key_1ee6 = { 49 94 [2] 7b b6 [2] 7d 83 [2] 53 83 [2] 6c 9f }

  condition:
    any of them
}