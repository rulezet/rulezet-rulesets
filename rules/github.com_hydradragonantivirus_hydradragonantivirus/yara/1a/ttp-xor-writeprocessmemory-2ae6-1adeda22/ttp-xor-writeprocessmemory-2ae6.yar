rule TTP_XOR_WriteProcessMemory_2ae6 {
  strings:
    $key_2ae6 = { 7d 94 [2] 4f b6 [2] 49 83 [2] 67 83 [2] 58 9f }

  condition:
    any of them
}