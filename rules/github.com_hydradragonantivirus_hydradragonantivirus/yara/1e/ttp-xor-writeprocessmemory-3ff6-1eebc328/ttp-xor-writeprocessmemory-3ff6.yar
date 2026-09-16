rule TTP_XOR_WriteProcessMemory_3ff6 {
  strings:
    $key_3ff6 = { 68 84 [2] 5a a6 [2] 5c 93 [2] 72 93 [2] 4d 8f }

  condition:
    any of them
}