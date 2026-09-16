rule TTP_XOR_WriteProcessMemory_1eb0 {
  strings:
    $key_1eb0 = { 49 c2 [2] 7b e0 [2] 7d d5 [2] 53 d5 [2] 6c c9 }

  condition:
    any of them
}