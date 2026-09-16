rule TTP_XOR_WriteProcessMemory_1ed7 {
  strings:
    $key_1ed7 = { 49 a5 [2] 7b 87 [2] 7d b2 [2] 53 b2 [2] 6c ae }

  condition:
    any of them
}