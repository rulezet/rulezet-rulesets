rule TTP_XOR_WriteProcessMemory_18a0 {
  strings:
    $key_18a0 = { 4f d2 [2] 7d f0 [2] 7b c5 [2] 55 c5 [2] 6a d9 }

  condition:
    any of them
}