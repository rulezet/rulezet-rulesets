rule TTP_XOR_WriteProcessMemory_79f0 {
  strings:
    $key_79f0 = { 2e 82 [2] 1c a0 [2] 1a 95 [2] 34 95 [2] 0b 89 }

  condition:
    any of them
}