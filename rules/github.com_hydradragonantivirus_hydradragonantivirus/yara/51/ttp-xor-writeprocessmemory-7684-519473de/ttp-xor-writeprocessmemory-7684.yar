rule TTP_XOR_WriteProcessMemory_7684 {
  strings:
    $key_7684 = { 21 f6 [2] 13 d4 [2] 15 e1 [2] 3b e1 [2] 04 fd }

  condition:
    any of them
}