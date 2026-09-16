rule TTP_XOR_WriteProcessMemory_19b0 {
  strings:
    $key_19b0 = { 4e c2 [2] 7c e0 [2] 7a d5 [2] 54 d5 [2] 6b c9 }

  condition:
    any of them
}