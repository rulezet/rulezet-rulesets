rule TTP_XOR_WriteProcessMemory_4685 {
  strings:
    $key_4685 = { 11 f7 [2] 23 d5 [2] 25 e0 [2] 0b e0 [2] 34 fc }

  condition:
    any of them
}