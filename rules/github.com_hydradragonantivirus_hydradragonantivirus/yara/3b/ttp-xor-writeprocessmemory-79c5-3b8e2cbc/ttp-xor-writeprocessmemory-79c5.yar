rule TTP_XOR_WriteProcessMemory_79c5 {
  strings:
    $key_79c5 = { 2e b7 [2] 1c 95 [2] 1a a0 [2] 34 a0 [2] 0b bc }

  condition:
    any of them
}