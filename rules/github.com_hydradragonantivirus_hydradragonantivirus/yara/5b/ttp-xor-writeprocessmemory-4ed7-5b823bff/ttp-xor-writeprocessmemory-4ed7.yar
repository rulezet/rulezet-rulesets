rule TTP_XOR_WriteProcessMemory_4ed7 {
  strings:
    $key_4ed7 = { 19 a5 [2] 2b 87 [2] 2d b2 [2] 03 b2 [2] 3c ae }

  condition:
    any of them
}