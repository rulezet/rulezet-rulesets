rule TTP_XOR_WriteProcessMemory_2dd5 {
  strings:
    $key_2dd5 = { 7a a7 [2] 48 85 [2] 4e b0 [2] 60 b0 [2] 5f ac }

  condition:
    any of them
}