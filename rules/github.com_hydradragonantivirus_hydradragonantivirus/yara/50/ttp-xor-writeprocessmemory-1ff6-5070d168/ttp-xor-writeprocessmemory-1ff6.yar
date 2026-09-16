rule TTP_XOR_WriteProcessMemory_1ff6 {
  strings:
    $key_1ff6 = { 48 84 [2] 7a a6 [2] 7c 93 [2] 52 93 [2] 6d 8f }

  condition:
    any of them
}