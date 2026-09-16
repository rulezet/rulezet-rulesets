rule TTP_XOR_WriteProcessMemory_4684 {
  strings:
    $key_4684 = { 11 f6 [2] 23 d4 [2] 25 e1 [2] 0b e1 [2] 34 fd }

  condition:
    any of them
}