rule TTP_XOR_WriteProcessMemory_ecd0 {
  strings:
    $key_ecd0 = { bb a2 [2] 89 80 [2] 8f b5 [2] a1 b5 [2] 9e a9 }

  condition:
    any of them
}