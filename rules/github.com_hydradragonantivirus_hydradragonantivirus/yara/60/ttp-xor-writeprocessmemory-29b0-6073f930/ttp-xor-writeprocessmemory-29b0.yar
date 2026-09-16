rule TTP_XOR_WriteProcessMemory_29b0 {
  strings:
    $key_29b0 = { 7e c2 [2] 4c e0 [2] 4a d5 [2] 64 d5 [2] 5b c9 }

  condition:
    any of them
}