rule TTP_XOR_WriteProcessMemory_79c3 {
  strings:
    $key_79c3 = { 2e b1 [2] 1c 93 [2] 1a a6 [2] 34 a6 [2] 0b ba }

  condition:
    any of them
}