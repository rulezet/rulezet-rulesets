rule TTP_XOR_WriteProcessMemory_6dd5 {
  strings:
    $key_6dd5 = { 3a a7 [2] 08 85 [2] 0e b0 [2] 20 b0 [2] 1f ac }

  condition:
    any of them
}