rule TTP_XOR_WriteProcessMemory_15e7 {
  strings:
    $key_15e7 = { 42 95 [2] 70 b7 [2] 76 82 [2] 58 82 [2] 67 9e }

  condition:
    any of them
}