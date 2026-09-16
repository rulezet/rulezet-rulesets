rule TTP_XOR_WriteProcessMemory_19b1 {
  strings:
    $key_19b1 = { 4e c3 [2] 7c e1 [2] 7a d4 [2] 54 d4 [2] 6b c8 }

  condition:
    any of them
}