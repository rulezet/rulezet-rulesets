rule TTP_XOR_WriteProcessMemory_30f6 {
  strings:
    $key_30f6 = { 67 84 [2] 55 a6 [2] 53 93 [2] 7d 93 [2] 42 8f }

  condition:
    any of them
}