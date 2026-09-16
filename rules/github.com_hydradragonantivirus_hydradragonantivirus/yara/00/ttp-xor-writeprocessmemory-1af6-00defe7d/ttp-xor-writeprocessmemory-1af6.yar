rule TTP_XOR_WriteProcessMemory_1af6 {
  strings:
    $key_1af6 = { 4d 84 [2] 7f a6 [2] 79 93 [2] 57 93 [2] 68 8f }

  condition:
    any of them
}