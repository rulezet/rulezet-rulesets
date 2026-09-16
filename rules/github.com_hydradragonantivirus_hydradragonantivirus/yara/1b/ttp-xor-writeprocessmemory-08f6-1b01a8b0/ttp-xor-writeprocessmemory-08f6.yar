rule TTP_XOR_WriteProcessMemory_08f6 {
  strings:
    $key_08f6 = { 5f 84 [2] 6d a6 [2] 6b 93 [2] 45 93 [2] 7a 8f }

  condition:
    any of them
}