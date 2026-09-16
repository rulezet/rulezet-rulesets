rule TTP_XOR_WriteProcessMemory_79c6 {
  strings:
    $key_79c6 = { 2e b4 [2] 1c 96 [2] 1a a3 [2] 34 a3 [2] 0b bf }

  condition:
    any of them
}