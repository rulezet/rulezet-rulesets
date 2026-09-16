rule TTP_XOR_WriteProcessMemory_3dd5 {
  strings:
    $key_3dd5 = { 6a a7 [2] 58 85 [2] 5e b0 [2] 70 b0 [2] 4f ac }

  condition:
    any of them
}