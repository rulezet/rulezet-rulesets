rule TTP_XOR_WriteProcessMemory_69b1 {
  strings:
    $key_69b1 = { 3e c3 [2] 0c e1 [2] 0a d4 [2] 24 d4 [2] 1b c8 }

  condition:
    any of them
}