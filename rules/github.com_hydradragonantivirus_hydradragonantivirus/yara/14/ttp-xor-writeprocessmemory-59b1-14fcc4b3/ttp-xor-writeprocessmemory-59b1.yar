rule TTP_XOR_WriteProcessMemory_59b1 {
  strings:
    $key_59b1 = { 0e c3 [2] 3c e1 [2] 3a d4 [2] 14 d4 [2] 2b c8 }

  condition:
    any of them
}