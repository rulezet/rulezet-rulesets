rule TTP_XOR_WriteProcessMemory_08a0 {
  strings:
    $key_08a0 = { 5f d2 [2] 6d f0 [2] 6b c5 [2] 45 c5 [2] 7a d9 }

  condition:
    any of them
}