rule TTP_XOR_WriteProcessMemory_47e7 {
  strings:
    $key_47e7 = { 10 95 [2] 22 b7 [2] 24 82 [2] 0a 82 [2] 35 9e }

  condition:
    any of them
}