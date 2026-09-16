rule TTP_XOR_WriteProcessMemory_4eb1 {
  strings:
    $key_4eb1 = { 19 c3 [2] 2b e1 [2] 2d d4 [2] 03 d4 [2] 3c c8 }

  condition:
    any of them
}