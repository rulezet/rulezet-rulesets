rule TTP_XOR_WriteProcessMemory_79c2 {
  strings:
    $key_79c2 = { 2e b0 [2] 1c 92 [2] 1a a7 [2] 34 a7 [2] 0b bb }

  condition:
    any of them
}