rule TTP_XOR_WriteProcessMemory_79f5 {
  strings:
    $key_79f5 = { 2e 87 [2] 1c a5 [2] 1a 90 [2] 34 90 [2] 0b 8c }

  condition:
    any of them
}