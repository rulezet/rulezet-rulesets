rule TTP_XOR_WriteProcessMemory_5684 {
  strings:
    $key_5684 = { 01 f6 [2] 33 d4 [2] 35 e1 [2] 1b e1 [2] 24 fd }

  condition:
    any of them
}