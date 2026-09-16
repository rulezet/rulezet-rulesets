rule TTP_XOR_WriteProcessMemory_4af6 {
  strings:
    $key_4af6 = { 1d 84 [2] 2f a6 [2] 29 93 [2] 07 93 [2] 38 8f }

  condition:
    any of them
}