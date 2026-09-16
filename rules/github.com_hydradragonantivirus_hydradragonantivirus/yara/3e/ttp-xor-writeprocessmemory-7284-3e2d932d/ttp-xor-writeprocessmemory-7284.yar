rule TTP_XOR_WriteProcessMemory_7284 {
  strings:
    $key_7284 = { 25 f6 [2] 17 d4 [2] 11 e1 [2] 3f e1 [2] 00 fd }

  condition:
    any of them
}