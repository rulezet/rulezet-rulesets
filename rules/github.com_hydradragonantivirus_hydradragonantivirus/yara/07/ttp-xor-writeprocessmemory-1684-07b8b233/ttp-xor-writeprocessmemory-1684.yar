rule TTP_XOR_WriteProcessMemory_1684 {
  strings:
    $key_1684 = { 41 f6 [2] 73 d4 [2] 75 e1 [2] 5b e1 [2] 64 fd }

  condition:
    any of them
}