rule TTP_XOR_WriteProcessMemory_5f84 {
  strings:
    $key_5f84 = { 08 f6 [2] 3a d4 [2] 3c e1 [2] 12 e1 [2] 2d fd }

  condition:
    any of them
}