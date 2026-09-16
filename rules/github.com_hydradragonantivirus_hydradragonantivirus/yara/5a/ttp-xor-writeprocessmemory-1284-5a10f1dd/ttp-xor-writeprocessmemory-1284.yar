rule TTP_XOR_WriteProcessMemory_1284 {
  strings:
    $key_1284 = { 45 f6 [2] 77 d4 [2] 71 e1 [2] 5f e1 [2] 60 fd }

  condition:
    any of them
}