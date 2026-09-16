rule TTP_XOR_WriteProcessMemory_69f0 {
  strings:
    $key_69f0 = { 3e 82 [2] 0c a0 [2] 0a 95 [2] 24 95 [2] 1b 89 }

  condition:
    any of them
}