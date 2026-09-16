rule TTP_XOR_WriteProcessMemory_2eb1 {
  strings:
    $key_2eb1 = { 79 c3 [2] 4b e1 [2] 4d d4 [2] 63 d4 [2] 5c c8 }

  condition:
    any of them
}