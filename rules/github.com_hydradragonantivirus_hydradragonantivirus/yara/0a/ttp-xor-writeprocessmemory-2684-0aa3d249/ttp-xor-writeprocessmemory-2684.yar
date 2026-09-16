rule TTP_XOR_WriteProcessMemory_2684 {
  strings:
    $key_2684 = { 71 f6 [2] 43 d4 [2] 45 e1 [2] 6b e1 [2] 54 fd }

  condition:
    any of them
}