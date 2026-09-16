rule TTP_XOR_WriteProcessMemory_2ed7 {
  strings:
    $key_2ed7 = { 79 a5 [2] 4b 87 [2] 4d b2 [2] 63 b2 [2] 5c ae }

  condition:
    any of them
}