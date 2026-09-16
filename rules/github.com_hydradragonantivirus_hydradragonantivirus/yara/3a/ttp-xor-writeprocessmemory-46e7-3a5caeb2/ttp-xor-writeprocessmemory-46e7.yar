rule TTP_XOR_WriteProcessMemory_46e7 {
  strings:
    $key_46e7 = { 11 95 [2] 23 b7 [2] 25 82 [2] 0b 82 [2] 34 9e }

  condition:
    any of them
}