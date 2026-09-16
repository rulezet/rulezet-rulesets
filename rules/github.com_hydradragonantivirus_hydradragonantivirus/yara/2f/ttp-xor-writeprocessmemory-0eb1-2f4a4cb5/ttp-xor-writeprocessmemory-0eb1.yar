rule TTP_XOR_WriteProcessMemory_0eb1 {
  strings:
    $key_0eb1 = { 59 c3 [2] 6b e1 [2] 6d d4 [2] 43 d4 [2] 7c c8 }

  condition:
    any of them
}