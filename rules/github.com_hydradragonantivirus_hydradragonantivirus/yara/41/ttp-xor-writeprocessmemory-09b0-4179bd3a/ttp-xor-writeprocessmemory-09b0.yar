rule TTP_XOR_WriteProcessMemory_09b0 {
  strings:
    $key_09b0 = { 5e c2 [2] 6c e0 [2] 6a d5 [2] 44 d5 [2] 7b c9 }

  condition:
    any of them
}