rule TTP_XOR_WriteProcessMemory_2685 {
  strings:
    $key_2685 = { 71 f7 [2] 43 d5 [2] 45 e0 [2] 6b e0 [2] 54 fc }

  condition:
    any of them
}