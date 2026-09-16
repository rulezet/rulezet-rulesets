rule TTP_XOR_WriteProcessMemory_5ce7 {
  strings:
    $key_5ce7 = { 0b 95 [2] 39 b7 [2] 3f 82 [2] 11 82 [2] 2e 9e }

  condition:
    any of them
}