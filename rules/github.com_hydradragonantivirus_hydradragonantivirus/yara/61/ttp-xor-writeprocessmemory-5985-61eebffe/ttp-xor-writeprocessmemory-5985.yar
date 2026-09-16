rule TTP_XOR_WriteProcessMemory_5985 {
  strings:
    $key_5985 = { 0e f7 [2] 3c d5 [2] 3a e0 [2] 14 e0 [2] 2b fc }

  condition:
    any of them
}