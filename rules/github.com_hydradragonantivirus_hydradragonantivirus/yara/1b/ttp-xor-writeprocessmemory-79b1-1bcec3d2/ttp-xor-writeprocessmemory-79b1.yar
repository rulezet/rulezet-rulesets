rule TTP_XOR_WriteProcessMemory_79b1 {
  strings:
    $key_79b1 = { 2e c3 [2] 1c e1 [2] 1a d4 [2] 34 d4 [2] 0b c8 }

  condition:
    any of them
}