rule TTP_XOR_WriteProcessMemory_278c {
  strings:
    $key_278c = { 70 fe [2] 42 dc [2] 44 e9 [2] 6a e9 [2] 55 f5 }

  condition:
    any of them
}